package main

import (
	"context"
	"crypto/tls"
	"embed"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/gorilla/mux"
	"github.com/mitchellh/go-homedir"
	"github.com/peterbourgon/ff/v3/ffcli"
	"go.etcd.io/bbolt"
	"go.uber.org/zap"

	"github.com/dstotijn/hetty/pkg/ai"
	"github.com/dstotijn/hetty/pkg/annotation"
	"github.com/dstotijn/hetty/pkg/api"
	"github.com/dstotijn/hetty/pkg/asm"
	"github.com/dstotijn/hetty/pkg/assetgraph"
	"github.com/dstotijn/hetty/pkg/authz"
	"github.com/dstotijn/hetty/pkg/browser"
	"github.com/dstotijn/hetty/pkg/chrome"
	"github.com/dstotijn/hetty/pkg/collab"
	"github.com/dstotijn/hetty/pkg/db/bolt"
	"github.com/dstotijn/hetty/pkg/discovery"
	"github.com/dstotijn/hetty/pkg/ext"
	"github.com/dstotijn/hetty/pkg/exttool"
	"github.com/dstotijn/hetty/pkg/intruder"
	"github.com/dstotijn/hetty/pkg/monitor"
	"github.com/dstotijn/hetty/pkg/msf"
	"github.com/dstotijn/hetty/pkg/osint"
	"github.com/dstotijn/hetty/pkg/paramminer"
	"github.com/dstotijn/hetty/pkg/proj"
	"github.com/dstotijn/hetty/pkg/proxy"
	"github.com/dstotijn/hetty/pkg/proxy/intercept"
	"github.com/dstotijn/hetty/pkg/ratelimit"
	"github.com/dstotijn/hetty/pkg/recon"
	"github.com/dstotijn/hetty/pkg/reqlog"
	"github.com/dstotijn/hetty/pkg/rules"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/scope"
	"github.com/dstotijn/hetty/pkg/sender"
	"github.com/dstotijn/hetty/pkg/session"
	"github.com/dstotijn/hetty/pkg/sessionflow"
	"github.com/dstotijn/hetty/pkg/sitemap"
	"github.com/dstotijn/hetty/pkg/spider"
	"github.com/dstotijn/hetty/pkg/template"
	"github.com/dstotijn/hetty/pkg/vault"
	"github.com/dstotijn/hetty/pkg/workflow"
	"github.com/dstotijn/hetty/pkg/wslog"
)

var version = "0.0.0"

//go:embed admin
//go:embed admin/_next/static
//go:embed admin/_next/static/chunks/pages/*.js
//go:embed admin/_next/static/*/*.js
var adminContent embed.FS

var hettyUsage = `
Usage:
    hetty [flags] [subcommand] [flags]

Runs an HTTP server with (MITM) proxy, GraphQL service, and a web based admin interface.

Options:
    --cert         Path to root CA certificate. Creates file if it doesn't exist. (Default: "~/.hetty/hetty_cert.pem")
    --key          Path to root CA private key. Creates file if it doesn't exist. (Default: "~/.hetty/hetty_key.pem")
    --db           Database file path. Creates file if it doesn't exist. (Default: "~/.hetty/hetty.db")
    --addr         TCP address for HTTP server to listen on, in the form \"host:port\". (Default: ":8080")
    --chrome       Launch Chrome with proxy settings applied and certificate errors ignored. (Default: false)
    --verbose      Enable verbose logging.
    --json         Encode logs as JSON, instead of pretty/human readable output.
    --version, -v  Output version.
    --help, -h     Output this usage text.

Subcommands:
    - cert  Certificate management

Run ` + "`hetty <subcommand> --help`" + ` for subcommand specific usage instructions.

Visit https://hetty.xyz to learn more about Hetty.
`

type HettyCommand struct {
	config *Config

	cert      string
	key       string
	db        string
	addr      string
	chrome    bool
	version   bool
	dnsAddr   string
	dnsDomain string
	rate        float64
	aiKey       string
	aiModel     string
	upstream    string
	shodanKey   string
	msfURL      string
	msfUser     string
	msfPass     string
	msfInsecure bool
}

func NewHettyCommand() (*ffcli.Command, *Config) {
	cmd := HettyCommand{
		config: &Config{},
	}

	fs := flag.NewFlagSet("hetty", flag.ExitOnError)

	fs.StringVar(&cmd.cert, "cert", "~/.hetty/hetty_cert.pem",
		"Path to root CA certificate. Creates a new certificate if file doesn't exist.")
	fs.StringVar(&cmd.key, "key", "~/.hetty/hetty_key.pem",
		"Path to root CA private key. Creates a new private key if file doesn't exist.")
	fs.StringVar(&cmd.db, "db", "~/.hetty/hetty.db", "Database file path. Creates file if it doesn't exist.")
	fs.StringVar(&cmd.addr, "addr", ":8080", "TCP address to listen on, in the form \"host:port\".")
	fs.BoolVar(&cmd.chrome, "chrome", false, "Launch Chrome with proxy settings applied and certificate errors ignored.")
	fs.BoolVar(&cmd.version, "version", false, "Output version.")
	fs.BoolVar(&cmd.version, "v", false, "Output version.")
	fs.StringVar(&cmd.dnsAddr, "dns-addr", "", "UDP address for the OOB DNS collaborator listener (e.g. \":53\"). Disabled when empty.")
	fs.StringVar(&cmd.dnsDomain, "dns-domain", "", "Base domain delegated to the DNS collaborator (e.g. \"oob.example.com\").")
	fs.Float64Var(&cmd.rate, "rate", 0, "Global request-rate cap (requests/sec) for the scanner, intruder and spider. 0 = unthrottled.")
	fs.StringVar(&cmd.aiKey, "ai-key", "", "Anthropic API key enabling the AI analyst. Falls back to the ANTHROPIC_API_KEY env var.")
	fs.StringVar(&cmd.aiModel, "ai-model", "", "Model for the AI analyst (default: claude-opus-4-8).")
	fs.StringVar(&cmd.upstream, "upstream-proxy", "",
		"Route outbound traffic through an upstream proxy (http://, https:// or socks5:// URL). Disabled when empty.")
	fs.StringVar(&cmd.shodanKey, "shodan-key", "", "Shodan API key for OSINT host lookups. Falls back to SHODAN_API_KEY.")
	fs.StringVar(&cmd.msfURL, "msf-url", "", "Metasploit RPC endpoint for auto-exploitation, e.g. https://127.0.0.1:55553/api/. Disabled when empty.")
	fs.StringVar(&cmd.msfUser, "msf-user", "msf", "Metasploit RPC username.")
	fs.StringVar(&cmd.msfPass, "msf-pass", "", "Metasploit RPC password.")
	fs.BoolVar(&cmd.msfInsecure, "msf-insecure", true, "Skip TLS verification for the Metasploit RPC endpoint (self-signed by default).")

	cmd.config.RegisterFlags(fs)

	return &ffcli.Command{
		Name:    "hetty",
		FlagSet: fs,
		Subcommands: []*ffcli.Command{
			NewCertCommand(cmd.config),
			newScanCommand(),
			newMCPCommand(),
			newSweepCommand(),
		},
		Exec: cmd.Exec,
		UsageFunc: func(*ffcli.Command) string {
			return hettyUsage
		},
	}, cmd.config
}

func (cmd *HettyCommand) Exec(ctx context.Context, _ []string) error {
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt)
	defer stop()

	if cmd.version {
		fmt.Fprint(os.Stdout, version+"\n")
		return nil
	}

	mainLogger := cmd.config.logger.Named("main")

	listenHost, listenPort, err := net.SplitHostPort(cmd.addr)
	if err != nil {
		mainLogger.Fatal("Failed to parse listening address.", zap.Error(err))
	}

	url := fmt.Sprintf("http://%v:%v", listenHost, listenPort)
	if listenHost == "" || listenHost == "0.0.0.0" || listenHost == "127.0.0.1" || listenHost == "::1" {
		url = fmt.Sprintf("http://localhost:%v", listenPort)
	}

	// Expand `~` in filepaths.
	caCertFile, err := homedir.Expand(cmd.cert)
	if err != nil {
		cmd.config.logger.Fatal("Failed to parse CA certificate filepath.", zap.Error(err))
	}

	caKeyFile, err := homedir.Expand(cmd.key)
	if err != nil {
		cmd.config.logger.Fatal("Failed to parse CA private key filepath.", zap.Error(err))
	}

	dbPath, err := homedir.Expand(cmd.db)
	if err != nil {
		cmd.config.logger.Fatal("Failed to parse database path.", zap.Error(err))
	}

	// Load existing CA certificate and key from disk, or generate and write
	// to disk if no files exist yet.
	caCert, caKey, err := proxy.LoadOrCreateCA(caKeyFile, caCertFile)
	if err != nil {
		cmd.config.logger.Fatal("Failed to load or create CA key pair.", zap.Error(err))
	}

	dbLogger := cmd.config.logger.Named("boltdb").Sugar()
	boltOpts := *bbolt.DefaultOptions
	boltOpts.Logger = &bolt.Logger{SugaredLogger: dbLogger}

	boltDB, err := bolt.OpenDatabase(dbPath, &boltOpts)
	if err != nil {
		cmd.config.logger.Fatal("Failed to open database.", zap.Error(err))
	}
	defer boltDB.Close()

	scope := &scope.Scope{}

	// Upstream proxy (optional): route all outbound tool traffic through an
	// HTTP/HTTPS/SOCKS5 proxy. http.Transport handles all three schemes.
	var upstreamURL *neturl.URL
	if cmd.upstream != "" {
		upstreamURL, err = neturl.Parse(cmd.upstream)
		if err != nil {
			cmd.config.logger.Fatal("Invalid --upstream-proxy URL.", zap.Error(err))
		}
		mainLogger.Info(fmt.Sprintf("Routing outbound traffic through upstream proxy %v ...", cmd.upstream))
	}

	reqLogService := reqlog.NewService(reqlog.Config{
		Scope:      scope,
		Repository: boltDB,
		Logger:     cmd.config.logger.Named("reqlog").Sugar(),
	})

	interceptService := intercept.NewService(intercept.Config{
		Logger: cmd.config.logger.Named("intercept").Sugar(),
	})

	senderCfg := sender.Config{
		Repository:    boltDB,
		ReqLogService: reqLogService,
	}
	if upstreamURL != nil {
		senderCfg.HTTPClient = proxyHTTPClient(upstreamURL, 30*time.Second, true)
	}
	senderService := sender.NewService(senderCfg)

	scanCfg := scan.Config{
		Repository: boltDB,
		Options:    scan.DefaultOptions(),
		Logger:     cmd.config.logger.Named("scan").Sugar(),
	}
	if upstreamURL != nil {
		scanCfg.HTTPClient = proxyHTTPClient(upstreamURL, 20*time.Second, false)
	}
	scanService := scan.NewService(scanCfg)

	rulesEngine := rules.NewEngine()
	intruderEngine := intruder.NewEngine()
	if upstreamURL != nil {
		intruderEngine.SetProxyURL(upstreamURL)
	}
	spiderCrawler := spider.New()

	// Global request-rate cap shared across the active tools (--rate).
	if cmd.rate > 0 {
		sharedLimiter := ratelimit.New(ratelimit.Config{RequestsPerSecond: cmd.rate})
		scanService.SetLimiter(sharedLimiter)
		intruderEngine.SetLimiter(sharedLimiter)
		spiderCrawler.SetLimiter(sharedLimiter)
	}

	collabServer := collab.NewServer(url + "/oob")
	scanService.SetOOB(collabServer)

	// Out-of-band DNS collaborator (optional).
	if cmd.dnsDomain != "" {
		collabServer.SetDNSDomain(cmd.dnsDomain)
	}
	if cmd.dnsAddr != "" {
		dnsConn, err := net.ListenPacket("udp", cmd.dnsAddr)
		if err != nil {
			mainLogger.Warn("Failed to start DNS collaborator listener.", zap.Error(err))
		} else {
			go func() {
				if err := collabServer.ServeDNS(ctx, dnsConn, nil); err != nil && ctx.Err() == nil {
					mainLogger.Warn("DNS collaborator listener stopped.", zap.Error(err))
				}
			}()
			mainLogger.Info(fmt.Sprintf("OOB DNS collaborator listening on %v ...", cmd.dnsAddr))
		}
	}

	// New bug-bounty tooling services.
	sessionStore := session.NewStore()
	authzEngine := authz.NewEngine(authz.Config{})
	discoveryEngine := discovery.New()
	sitemapStore := sitemap.New()
	annotationStore := annotation.New()
	paramMinerEngine := paramminer.New()
	wsStore := wslog.New()
	extStore := ext.NewStore()
	macroStore := sessionflow.NewStore()
	macroEngine := sessionflow.New()
	if upstreamURL != nil {
		macroEngine.SetTransport(proxyTransport(upstreamURL))
	}

	// Attack-surface management (Sn1per-style): shared recon engine, OSINT,
	// optional Metasploit, and the scan-mode orchestrator.
	reconEngine := recon.New()
	shodanKey := cmd.shodanKey
	if shodanKey == "" {
		shodanKey = os.Getenv("SHODAN_API_KEY")
	}
	shodanClient := osint.New(shodanKey)
	msfClient := msf.New(msf.Config{URL: cmd.msfURL, User: cmd.msfUser, Pass: cmd.msfPass, Insecure: cmd.msfInsecure})
	if msfClient.Enabled() {
		mainLogger.Info("Metasploit auto-exploitation (NUKE) enabled.")
	}
	asmStore := asm.NewStore()
	extToolRunner := exttool.NewRunner(exttool.DefaultCatalog(), 0)

	// Save destinations, monitoring schedules, and workflows (engines built below
	// once the template engine is available).
	vaultStore := vault.NewStore()
	monitorStore := monitor.NewStore()
	workflowStore := workflow.NewStore()
	assetGraph := assetgraph.New()

	// AI analyst (optional). Key from flag, falling back to the environment.
	aiKey := cmd.aiKey
	if aiKey == "" {
		aiKey = os.Getenv("ANTHROPIC_API_KEY")
	}
	aiClient := ai.NewClient(ai.Config{APIKey: aiKey, Model: cmd.aiModel})
	if aiClient.Enabled() {
		mainLogger.Info(fmt.Sprintf("AI analyst enabled (model: %v).", aiClient.Model()))
	}

	// Templated scanner: built-in templates plus any under ~/.hetty/templates.
	tmplEngine := template.New()
	loadedTemplates := template.Builtins()
	if tmplDir, err := homedir.Expand("~/.hetty/templates"); err == nil {
		if userTemplates, errs := template.LoadDir(tmplDir); len(userTemplates) > 0 {
			loadedTemplates = append(loadedTemplates, userTemplates...)
			mainLogger.Info(fmt.Sprintf("Loaded %d template(s) from %v.", len(userTemplates), tmplDir))
			for _, e := range errs {
				mainLogger.Debug("Template load error.", zap.Error(e))
			}
		}
	}

	// Durability: restore persisted tool state, then flush periodically and on
	// shutdown so the site map, auth profiles, annotations, collaborator
	// interactions and WebSocket history survive restarts.
	toolStores := map[string]toolStore{
		"sitemap":     sitemapStore,
		"sessions":    sessionStore,
		"annotations": annotationStore,
		"collab":      collabServer,
		"wslog":       wsStore,
		"ext":         extStore,
		"macros":      macroStore,
		"asm":         asmStore,
		"vault":       vaultStore,
		"monitor":     monitorStore,
		"workflows":   workflowStore,
		"assets":      assetGraph,
	}
	restoreStores(boltDB, toolStores, mainLogger)
	lastFlush := make(map[string][]byte)
	flushTicker := time.NewTicker(15 * time.Second)
	defer flushTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-flushTicker.C:
				flushStores(boltDB, toolStores, lastFlush, mainLogger)
			}
		}
	}()

	extDir, err := homedir.Expand("~/.hetty/extensions")
	if err != nil {
		cmd.config.logger.Fatal("Failed to parse extensions dir.", zap.Error(err))
	}
	extEngine := ext.NewEngine(ext.Config{
		Dir:         extDir,
		ScanService: scanService,
		Logger:      cmd.config.logger.Named("ext").Sugar(),
		Store:       extStore,
		History:     &historyAdapter{svc: reqLogService},
		Sitemap:     &sitemapAdapter{store: sitemapStore},
		Collab:      &collabAdapter{srv: collabServer},
		Intruder:    intruderEngine,
	})
	if _, err := extEngine.LoadAll(); err != nil {
		mainLogger.Warn("Failed to load extensions.", zap.Error(err))
	}

	projService, err := proj.NewService(proj.Config{
		Repository:       boltDB,
		InterceptService: interceptService,
		ReqLogService:    reqLogService,
		SenderService:    senderService,
		ScanService:      scanService,
		Scope:            scope,
	})
	if err != nil {
		cmd.config.logger.Fatal("Failed to create new projects service.", zap.Error(err))
	}

	proxy, err := proxy.NewProxy(proxy.Config{
		CACert:        caCert,
		CAKey:         caKey,
		Logger:        cmd.config.logger.Named("proxy").Sugar(),
		UpstreamProxy: upstreamURL,
	})
	if err != nil {
		cmd.config.logger.Fatal("Failed to create new proxy.", zap.Error(err))
	}

	proxy.UseRequestModifier(reqLogService.RequestModifier)
	proxy.UseResponseModifier(reqLogService.ResponseModifier)
	proxy.UseRequestModifier(interceptService.RequestModifier)
	proxy.UseResponseModifier(interceptService.ResponseModifier)

	// Passive scanning of proxied responses.
	proxy.UseResponseModifier(scanService.ResponseModifier)

	// Aggregate proxied traffic into the site map.
	proxy.UseResponseModifier(sitemapStore.ResponseModifier)

	// Intercept and log WebSocket frames.
	proxy.SetWebSocketLogger(wsStore)

	// Extension request/response hooks.
	proxy.UseRequestModifier(extEngine.RequestModifier)
	proxy.UseResponseModifier(extEngine.ResponseModifier)

	// Match & replace rules (run last so they have the final say).
	proxy.UseRequestModifier(rulesEngine.RequestModifier)
	proxy.UseResponseModifier(rulesEngine.ResponseModifier)

	fsSub, err := fs.Sub(adminContent, "admin")
	if err != nil {
		cmd.config.logger.Fatal("Failed to construct file system subtree from admin dir.", zap.Error(err))
	}

	adminHandler := http.FileServer(http.FS(fsSub))
	router := mux.NewRouter().SkipClean(true)
	adminRouter := router.MatcherFunc(func(req *http.Request, match *mux.RouteMatch) bool {
		hostname, _ := os.Hostname()
		host, _, _ := net.SplitHostPort(req.Host)

		// Serve local admin routes when either:
		// - The `Host` is well-known, e.g. `hetty.proxy`, `localhost:[port]`
		//   or the listen addr `[host]:[port]`.
		// - The request is not for TLS proxying (e.g. no `CONNECT`) and not
		//   for proxying an external URL. E.g. Request-Line (RFC 7230, Section 3.1.1)
		//   has no scheme.
		return strings.EqualFold(host, hostname) ||
			req.Host == "hetty.proxy" ||
			req.Host == fmt.Sprintf("%v:%v", "localhost", listenPort) ||
			req.Host == fmt.Sprintf("%v:%v", listenHost, listenPort) ||
			req.Method != http.MethodConnect && !strings.HasPrefix(req.RequestURI, "http://")
	}).Subrouter().StrictSlash(true)

	// GraphQL server.
	gqlEndpoint := "/api/graphql/"
	adminRouter.Path(gqlEndpoint).Handler(api.HTTPHandler(&api.Resolver{
		ProjectService:    projService,
		RequestLogService: reqLogService,
		InterceptService:  interceptService,
		SenderService:     senderService,
	}, gqlEndpoint))

	// Scan-mode orchestrator binds the recon/scan/template/MSF engines.
	asmEngine := asm.New(newASMToolbox(reconEngine, scanService, tmplEngine, loadedTemplates, msfClient))

	// Monitor + workflow engines + the background scheduler.
	plat := &platform{
		recon:     reconEngine,
		scan:      scanService,
		tmpl:      tmplEngine,
		templates: loadedTemplates,
		exttools:  extToolRunner,
		graph:     assetGraph,
	}
	monitorEngine := monitor.New(monitorStore, plat.probe, sendAlert)
	workflowEngine := workflow.New(plat.workflowStep)

	// Scheduled runs can snapshot themselves to a saved vault destination.
	monitorEngine.SetSaver(func(s monitor.Schedule, snapshot []byte) {
		dest, ok := vaultStore.Get(s.SaveTo)
		if !ok {
			return
		}
		key := fmt.Sprintf("hetty/monitor/%s/%s.json", s.Name, time.Now().UTC().Format("20060102T150405Z"))
		if _, err := vault.Save(context.Background(), dest.Config, key, snapshot, "application/json"); err != nil {
			mainLogger.Warn("Monitor auto-save failed.", zap.Error(err))
		}
	})

	schedTicker := time.NewTicker(30 * time.Second)
	defer schedTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-schedTicker.C:
				monitorEngine.Tick(time.Now())
			}
		}
	}()

	// REST API for the new tooling.
	toolsAPI := (&restAPI{
		scanner:     scanService,
		intruder:    intruderEngine,
		rules:       rulesEngine,
		ext:         extEngine,
		collab:      collabServer,
		proj:        projService,
		spider:      spiderCrawler,
		authz:       authzEngine,
		sessions:    sessionStore,
		discovery:   discoveryEngine,
		sitemap:     sitemapStore,
		annotations: annotationStore,
		paramminer:  paramMinerEngine,
		wslog:       wsStore,
		ai:          aiClient,
		tmplEngine:  tmplEngine,
		templates:   loadedTemplates,
		recon:       reconEngine,
		browser:     browser.New(),
		macros:      macroStore,
		macroEngine: macroEngine,
		upstream:    cmd.upstream,
		asmStore:    asmStore,
		asmEngine:   asmEngine,
		shodan:      shodanClient,
		msf:         msfClient,
		exttools:    extToolRunner,
		vault:       vaultStore,
		monitor:     monitorStore,
		monitorEngine: monitorEngine,
		workflows:   workflowStore,
		workflowEngine: workflowEngine,
		graph:       assetGraph,
	}).Handler()
	for _, prefix := range []string{
		"/api/scanner", "/api/intruder", "/api/decoder", "/api/comparer",
		"/api/sequencer", "/api/rules", "/api/extensions", "/api/collab", "/api/spider",
		"/api/authz", "/api/session", "/api/discovery", "/api/sitemap", "/api/jwt",
		"/api/annotations", "/api/paramminer", "/api/gql", "/api/smuggle", "/api/websocket",
		"/api/ai", "/api/wordlists", "/api/template", "/api/recon", "/api/browser",
		"/api/macros", "/api/poc", "/api/wsrepeater", "/api/settings",
		"/api/portscan", "/api/tlsscan", "/api/wafdetect", "/api/screenshot",
		"/api/osint", "/api/msf", "/api/asm", "/api/exttools",
		"/api/vault", "/api/monitor", "/api/workflows", "/api/assets",
	} {
		adminRouter.PathPrefix(prefix).Handler(toolsAPI)
	}

	// Out-of-band collaborator callback endpoint. Mounted under /oob/ so it does
	// not shadow the /collab/ admin UI page.
	adminRouter.PathPrefix("/oob/").Handler(http.StripPrefix("/oob", collabServer.Handler()))

	// Admin interface.
	adminRouter.PathPrefix("").Handler(adminHandler)

	// Fallback (default) is the Proxy handler.
	router.PathPrefix("").Handler(proxy)

	httpServer := &http.Server{
		Addr:         cmd.addr,
		Handler:      router,
		TLSNextProto: map[string]func(*http.Server, *tls.Conn, http.Handler){}, // Disable HTTP/2
		ErrorLog:     zap.NewStdLog(cmd.config.logger.Named("http")),
	}

	go func() {
		mainLogger.Info(fmt.Sprintf("Hetty (v%v) is running on %v ...", version, cmd.addr))
		mainLogger.Info(fmt.Sprintf("\x1b[%dm%s\x1b[0m", uint8(32), "Get started at "+url))

		err := httpServer.ListenAndServe()
		if err != http.ErrServerClosed {
			mainLogger.Fatal("HTTP server closed unexpected.", zap.Error(err))
		}
	}()

	if cmd.chrome {
		ctx, cancel := chrome.NewExecAllocator(ctx, chrome.Config{
			ProxyServer:      url,
			ProxyBypassHosts: []string{url},
		})
		defer cancel()

		taskCtx, cancel := chromedp.NewContext(ctx)
		defer cancel()

		err = chromedp.Run(taskCtx, chromedp.Navigate(url))

		switch {
		case errors.Is(err, exec.ErrNotFound):
			mainLogger.Info("Chrome executable not found.")
		case err != nil:
			mainLogger.Error(fmt.Sprintf("Failed to navigate to %v.", url), zap.Error(err))
		default:
			mainLogger.Info("Launched Chrome.")
		}
	}

	// Wait for interrupt signal.
	<-ctx.Done()
	// Restore signal, allowing "force quit".
	stop()

	mainLogger.Info("Shutting down HTTP server. Press Ctrl+C to force quit.")

	// Final flush of tool state before the database is closed.
	flushStores(boltDB, toolStores, lastFlush, mainLogger)

	// Note: We expect httpServer.Handler to handle timeouts, thus, we don't
	// need a context value with deadline here.
	//nolint:contextcheck
	err = httpServer.Shutdown(context.Background())
	if err != nil {
		return fmt.Errorf("failed to shutdown HTTP server: %w", err)
	}

	return nil
}
