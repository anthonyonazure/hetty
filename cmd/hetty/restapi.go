package main

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"time"
	"unicode/utf8"

	"github.com/gorilla/mux"
	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/ai"
	"github.com/dstotijn/hetty/pkg/annotation"
	"github.com/dstotijn/hetty/pkg/asm"
	"github.com/dstotijn/hetty/pkg/authz"
	"github.com/dstotijn/hetty/pkg/browser"
	"github.com/dstotijn/hetty/pkg/collab"
	"github.com/dstotijn/hetty/pkg/comparer"
	"github.com/dstotijn/hetty/pkg/decoder"
	"github.com/dstotijn/hetty/pkg/discovery"
	"github.com/dstotijn/hetty/pkg/ext"
	"github.com/dstotijn/hetty/pkg/exttool"
	"github.com/dstotijn/hetty/pkg/intruder"
	"github.com/dstotijn/hetty/pkg/msf"
	"github.com/dstotijn/hetty/pkg/osint"
	"github.com/dstotijn/hetty/pkg/paramminer"
	"github.com/dstotijn/hetty/pkg/proj"
	"github.com/dstotijn/hetty/pkg/recon"
	"github.com/dstotijn/hetty/pkg/report"
	"github.com/dstotijn/hetty/pkg/rules"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/sequencer"
	"github.com/dstotijn/hetty/pkg/session"
	"github.com/dstotijn/hetty/pkg/sessionflow"
	"github.com/dstotijn/hetty/pkg/sitemap"
	"github.com/dstotijn/hetty/pkg/spider"
	"github.com/dstotijn/hetty/pkg/template"
	"github.com/dstotijn/hetty/pkg/wslog"
)

type restAPI struct {
	scanner     *scan.Service
	intruder    *intruder.Engine
	rules       *rules.Engine
	ext         *ext.Engine
	collab      *collab.Server
	proj        *proj.Service
	spider      *spider.Crawler
	authz       *authz.Engine
	sessions    *session.Store
	discovery   *discovery.Engine
	sitemap     *sitemap.Store
	annotations *annotation.Store
	paramminer  *paramminer.Engine
	wslog       *wslog.Store
	ai          *ai.Client
	tmplEngine  *template.Engine
	templates   []*template.Template
	recon       *recon.Engine
	browser     *browser.Crawler
	macros      *sessionflow.Store
	macroEngine *sessionflow.Engine
	upstream    string
	asmStore    *asm.Store
	asmEngine   *asm.Engine
	shodan      *osint.Client
	msf         *msf.Client
	exttools    *exttool.Runner
}

func (a *restAPI) Handler() http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/api/scanner/scan", a.handleScannerScan).Methods(http.MethodPost)
	r.HandleFunc("/api/scanner/issues", a.handleScannerIssues).Methods(http.MethodGet)
	r.HandleFunc("/api/scanner/issues", a.handleScannerClear).Methods(http.MethodDelete)
	r.HandleFunc("/api/scanner/checks", a.handleScannerChecks).Methods(http.MethodGet)
	r.HandleFunc("/api/scanner/report", a.handleScannerReport).Methods(http.MethodGet)

	r.HandleFunc("/api/intruder/positions", a.handleIntruderPositions).Methods(http.MethodPost)
	r.HandleFunc("/api/intruder/run", a.handleIntruderRun).Methods(http.MethodPost)

	r.HandleFunc("/api/decoder/codecs", a.handleDecoderCodecs).Methods(http.MethodGet)
	r.HandleFunc("/api/decoder", a.handleDecoder).Methods(http.MethodPost)
	r.HandleFunc("/api/decoder/smart", a.handleDecoderSmart).Methods(http.MethodPost)

	r.HandleFunc("/api/comparer", a.handleComparer).Methods(http.MethodPost)
	r.HandleFunc("/api/sequencer", a.handleSequencer).Methods(http.MethodPost)

	r.HandleFunc("/api/spider/crawl", a.handleSpiderCrawl).Methods(http.MethodPost)
	r.HandleFunc("/api/scanner/crawl-scan", a.handleScannerCrawlScan).Methods(http.MethodPost)

	r.HandleFunc("/api/rules", a.handleRulesGet).Methods(http.MethodGet)
	r.HandleFunc("/api/rules", a.handleRulesSet).Methods(http.MethodPut)

	r.HandleFunc("/api/extensions", a.handleExtensionsList).Methods(http.MethodGet)
	r.HandleFunc("/api/extensions/reload", a.handleExtensionsReload).Methods(http.MethodPost)
	r.HandleFunc("/api/extensions/actions", a.handleExtActionsList).Methods(http.MethodGet)
	r.HandleFunc("/api/extensions/actions/run", a.handleExtActionRun).Methods(http.MethodPost)

	r.HandleFunc("/api/macros", a.handleMacrosList).Methods(http.MethodGet)
	r.HandleFunc("/api/macros", a.handleMacroSet).Methods(http.MethodPut)
	r.HandleFunc("/api/macros", a.handleMacroDelete).Methods(http.MethodDelete)
	r.HandleFunc("/api/macros/run", a.handleMacroRun).Methods(http.MethodPost)

	r.HandleFunc("/api/poc/csrf", a.handlePoCCSRF).Methods(http.MethodPost)
	r.HandleFunc("/api/poc/clickjacking", a.handlePoCClickjacking).Methods(http.MethodPost)

	r.HandleFunc("/api/wsrepeater", a.handleWSRepeater).Methods(http.MethodPost)

	r.HandleFunc("/api/settings", a.handleSettings).Methods(http.MethodGet)

	r.HandleFunc("/api/portscan", a.handlePortScan).Methods(http.MethodPost)
	r.HandleFunc("/api/tlsscan", a.handleTLSScan).Methods(http.MethodPost)
	r.HandleFunc("/api/wafdetect", a.handleWAFDetect).Methods(http.MethodPost)
	r.HandleFunc("/api/screenshot", a.handleScreenshot).Methods(http.MethodPost)
	r.HandleFunc("/api/osint/shodan", a.handleShodan).Methods(http.MethodPost)
	r.HandleFunc("/api/msf/status", a.handleMSFStatus).Methods(http.MethodGet)

	r.HandleFunc("/api/asm/workspaces", a.handleASMList).Methods(http.MethodGet)
	r.HandleFunc("/api/asm/workspaces", a.handleASMSet).Methods(http.MethodPut)
	r.HandleFunc("/api/asm/workspaces", a.handleASMDelete).Methods(http.MethodDelete)
	r.HandleFunc("/api/asm/workspace", a.handleASMGet).Methods(http.MethodGet)
	r.HandleFunc("/api/asm/run", a.handleASMRun).Methods(http.MethodPost)

	r.HandleFunc("/api/exttools", a.handleExtToolsList).Methods(http.MethodGet)
	r.HandleFunc("/api/exttools/run", a.handleExtToolRun).Methods(http.MethodPost)
	r.HandleFunc("/api/exttools/job", a.handleExtToolJob).Methods(http.MethodGet)
	r.HandleFunc("/api/exttools/stop", a.handleExtToolStop).Methods(http.MethodPost)

	r.HandleFunc("/api/collab/token", a.handleCollabToken).Methods(http.MethodPost)
	r.HandleFunc("/api/collab/interactions", a.handleCollabInteractions).Methods(http.MethodGet)

	r.HandleFunc("/api/authz/analyze", a.handleAuthzAnalyze).Methods(http.MethodPost)

	r.HandleFunc("/api/session/profiles", a.handleSessionList).Methods(http.MethodGet)
	r.HandleFunc("/api/session/profiles", a.handleSessionSet).Methods(http.MethodPut)
	r.HandleFunc("/api/session/profiles", a.handleSessionDelete).Methods(http.MethodDelete)

	r.HandleFunc("/api/discovery", a.handleDiscovery).Methods(http.MethodPost)

	r.HandleFunc("/api/paramminer", a.handleParamMiner).Methods(http.MethodPost)

	r.HandleFunc("/api/gql/introspect", a.handleGQLIntrospect).Methods(http.MethodPost)

	r.HandleFunc("/api/smuggle", a.handleSmuggle).Methods(http.MethodPost)

	r.HandleFunc("/api/websocket/connections", a.handleWSConnections).Methods(http.MethodGet)
	r.HandleFunc("/api/websocket/messages", a.handleWSMessages).Methods(http.MethodGet)
	r.HandleFunc("/api/websocket", a.handleWSClear).Methods(http.MethodDelete)

	r.HandleFunc("/api/wordlists", a.handleWordlists).Methods(http.MethodGet)
	r.HandleFunc("/api/wordlists/{name}", a.handleWordlist).Methods(http.MethodGet)

	r.HandleFunc("/api/template", a.handleTemplateList).Methods(http.MethodGet)
	r.HandleFunc("/api/template/run", a.handleTemplateRun).Methods(http.MethodPost)

	r.HandleFunc("/api/recon/subdomains", a.handleReconSubdomains).Methods(http.MethodPost)
	r.HandleFunc("/api/recon/fingerprint", a.handleReconFingerprint).Methods(http.MethodPost)

	r.HandleFunc("/api/browser/crawl", a.handleBrowserCrawl).Methods(http.MethodPost)

	r.HandleFunc("/api/ai/status", a.handleAIStatus).Methods(http.MethodGet)
	r.HandleFunc("/api/ai/triage", a.handleAITriage).Methods(http.MethodPost)
	r.HandleFunc("/api/ai/payloads", a.handleAIPayloads).Methods(http.MethodPost)
	r.HandleFunc("/api/ai/report", a.handleAIReport).Methods(http.MethodPost)

	r.HandleFunc("/api/sitemap", a.handleSitemap).Methods(http.MethodGet)
	r.HandleFunc("/api/sitemap", a.handleSitemapClear).Methods(http.MethodDelete)
	r.HandleFunc("/api/sitemap/ingest", a.handleSitemapIngest).Methods(http.MethodPost)

	r.HandleFunc("/api/jwt/parse", a.handleJWTParse).Methods(http.MethodPost)
	r.HandleFunc("/api/jwt/sign", a.handleJWTSign).Methods(http.MethodPost)
	r.HandleFunc("/api/jwt/alg-none", a.handleJWTAlgNone).Methods(http.MethodPost)
	r.HandleFunc("/api/jwt/brute", a.handleJWTBrute).Methods(http.MethodPost)

	r.HandleFunc("/api/annotations", a.handleAnnotationsList).Methods(http.MethodGet)
	r.HandleFunc("/api/annotations", a.handleAnnotationsSet).Methods(http.MethodPut)
	r.HandleFunc("/api/annotations", a.handleAnnotationsDelete).Methods(http.MethodDelete)

	return r
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

func readJSON(r *http.Request, v interface{}) error {
	defer r.Body.Close()
	return json.NewDecoder(r.Body).Decode(v)
}

func (a *restAPI) activeProjectID(r *http.Request) (ulid.ULID, bool) {
	if a.proj == nil {
		return ulid.ULID{}, false
	}
	p, err := a.proj.ActiveProject(r.Context())
	if err != nil {
		return ulid.ULID{}, false
	}
	return p.ID, true
}

type reqSpec struct {
	Method  string            `json:"method"`
	URL     string            `json:"url"`
	Proto   string            `json:"proto"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Profile string            `json:"profile"`
}

func (s reqSpec) template() (*scan.RequestTemplate, error) {
	u, err := url.Parse(s.URL)
	if err != nil {
		return nil, err
	}
	h := http.Header{}
	for k, v := range s.Headers {
		h.Set(k, v)
	}
	method := s.Method
	if method == "" {
		method = http.MethodGet
	}
	return scan.NewRequestTemplate(method, u, s.Proto, h, []byte(s.Body)), nil
}

func (a *restAPI) handleScannerScan(w http.ResponseWriter, r *http.Request) {
	projectID, ok := a.activeProjectID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no active project")
		return
	}
	var spec reqSpec
	if err := readJSON(r, &spec); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid body: "+err.Error())
		return
	}
	tmpl, err := spec.template()
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid request spec: "+err.Error())
		return
	}
	applyProfileToHeader(r.Context(), a.resolveProfile(spec.Profile), tmpl.Header)
	result, err := a.scanner.ScanRequest(r.Context(), projectID, tmpl)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"baseRequests": result.BaseRequests,
		"tasksRun":     result.TasksRun,
		"issues":       result.Issues,
	})
}

func (a *restAPI) handleScannerIssues(w http.ResponseWriter, r *http.Request) {
	projectID, ok := a.activeProjectID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no active project")
		return
	}
	issues, err := a.scanner.FindIssues(r.Context(), projectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"issues": issues})
}

func (a *restAPI) handleScannerClear(w http.ResponseWriter, r *http.Request) {
	projectID, ok := a.activeProjectID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no active project")
		return
	}
	if err := a.scanner.ClearIssues(r.Context(), projectID); err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "cleared"})
}

func (a *restAPI) handleScannerReport(w http.ResponseWriter, r *http.Request) {
	projectID, ok := a.activeProjectID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no active project")
		return
	}
	issues, err := a.scanner.FindIssues(r.Context(), projectID)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	title := "Hetty Scan Report"
	now := time.Now()

	switch r.URL.Query().Get("format") {
	case "md", "markdown":
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="hetty-report.md"`)
		_, _ = w.Write([]byte(report.Markdown(title, issues, now)))
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="hetty-report.html"`)
		_, _ = w.Write([]byte(report.HTML(title, issues, now)))
	}
}

func (a *restAPI) handleScannerChecks(w http.ResponseWriter, r *http.Request) {
	reg := a.scanner.Registry()
	type checkInfo struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	var out []checkInfo
	for _, c := range reg.ActiveChecks() {
		out = append(out, checkInfo{ID: c.ID(), Name: c.Name(), Kind: "active"})
	}
	for _, c := range reg.PassiveChecks() {
		out = append(out, checkInfo{ID: c.ID(), Name: c.Name(), Kind: "passive"})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"checks": out})
}

func (a *restAPI) handleIntruderPositions(w http.ResponseWriter, r *http.Request) {
	body := struct {
		Base   intruder.RequestSpec `json:"base"`
		Marker string               `json:"marker"`
	}{}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"positions": intruder.CountPositions(body.Base, body.Marker),
	})
}

func (a *restAPI) handleIntruderRun(w http.ResponseWriter, r *http.Request) {
	var body struct {
		intruder.Attack
		Profile string `json:"profile"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	applyProfileToIntruderBase(r.Context(), a.resolveProfile(body.Profile), &body.Attack.Base)
	summary, results, err := a.intruder.Run(r.Context(), body.Attack)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"summary": summary,
		"results": results,
	})
}

func (a *restAPI) handleDecoderCodecs(w http.ResponseWriter, r *http.Request) {
	type info struct {
		ID        string `json:"id"`
		Name      string `json:"name"`
		CanEncode bool   `json:"canEncode"`
		CanDecode bool   `json:"canDecode"`
	}
	var out []info
	for _, c := range decoder.Codecs() {
		out = append(out, info{ID: c.ID, Name: c.Name, CanEncode: c.CanEncode, CanDecode: c.CanDecode})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"codecs": out})
}

func (a *restAPI) handleDecoder(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Codec string `json:"codec"`
		Op    string `json:"op"`
		Input string `json:"input"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	out, err := decoder.Apply(body.Codec, decoder.Op(body.Op), []byte(body.Input))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, encodeOutput(out))
}

func (a *restAPI) handleDecoderSmart(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Input string `json:"input"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"steps": decoder.SmartDecode([]byte(body.Input)),
	})
}

func encodeOutput(b []byte) map[string]interface{} {
	out := map[string]interface{}{
		"outputBase64": base64.StdEncoding.EncodeToString(b),
		"isBinary":     !utf8.Valid(b),
	}
	if utf8.Valid(b) {
		out["output"] = string(b)
	}
	return out
}

func (a *restAPI) handleComparer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		A    string `json:"a"`
		B    string `json:"b"`
		Mode string `json:"mode"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	var res comparer.Result
	if body.Mode == "bytes" {
		res = comparer.DiffBytes(body.A, body.B)
	} else {
		res = comparer.DiffWords(body.A, body.B)
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *restAPI) handleSequencer(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Tokens []string `json:"tokens"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, sequencer.Analyze(body.Tokens))
}

func (a *restAPI) handleRulesGet(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]interface{}{"rules": a.rules.Rules()})
}

func (a *restAPI) handleRulesSet(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Rules []rules.Rule `json:"rules"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := a.rules.SetRules(body.Rules); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"rules": a.rules.Rules()})
}

func (a *restAPI) handleExtensionsList(w http.ResponseWriter, r *http.Request) {
	if a.ext == nil {
		writeJSON(w, http.StatusOK, map[string]interface{}{"extensions": []ext.Info{}})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"extensions": a.ext.Extensions()})
}

func (a *restAPI) handleExtensionsReload(w http.ResponseWriter, r *http.Request) {
	if a.ext == nil {
		writeErr(w, http.StatusServiceUnavailable, "extensions are disabled")
		return
	}
	infos, err := a.ext.LoadAll()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"extensions": infos})
}

func (a *restAPI) handleCollabToken(w http.ResponseWriter, r *http.Request) {
	if a.collab == nil {
		writeErr(w, http.StatusServiceUnavailable, "collaborator is disabled")
		return
	}
	token, u := a.collab.NewToken()
	resp := map[string]string{"token": token, "url": u}
	if dnsHost := a.collab.DNSHost(token); dnsHost != "" {
		resp["dnsHost"] = dnsHost
	}
	writeJSON(w, http.StatusOK, resp)
}

func (a *restAPI) handleCollabInteractions(w http.ResponseWriter, r *http.Request) {
	if a.collab == nil {
		writeErr(w, http.StatusServiceUnavailable, "collaborator is disabled")
		return
	}
	token := r.URL.Query().Get("token")
	if token == "" {
		writeErr(w, http.StatusBadRequest, "token query parameter required")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"interactions": a.collab.Interactions(token),
	})
}

func optsOrDefault(o spider.Options) spider.Options {
	if o.MaxPages == 0 && o.MaxDepth == 0 {
		return spider.DefaultOptions()
	}
	if o.MaxPages <= 0 {
		o.MaxPages = 100
	}
	return o
}

func (a *restAPI) handleSpiderCrawl(w http.ResponseWriter, r *http.Request) {
	if a.spider == nil {
		writeErr(w, http.StatusServiceUnavailable, "spider is disabled")
		return
	}
	var body struct {
		Seed    string         `json:"seed"`
		Options spider.Options `json:"options"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Seed == "" {
		writeErr(w, http.StatusBadRequest, "seed is required")
		return
	}
	res, err := a.spider.Crawl(r.Context(), body.Seed, optsOrDefault(body.Options))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (a *restAPI) handleScannerCrawlScan(w http.ResponseWriter, r *http.Request) {
	projectID, ok := a.activeProjectID(r)
	if !ok {
		writeErr(w, http.StatusBadRequest, "no active project")
		return
	}
	if a.spider == nil {
		writeErr(w, http.StatusServiceUnavailable, "spider is disabled")
		return
	}
	var body struct {
		Seed    string         `json:"seed"`
		Options spider.Options `json:"options"`
		Profile string         `json:"profile"`
	}
	if err := readJSON(r, &body); err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if body.Seed == "" {
		writeErr(w, http.StatusBadRequest, "seed is required")
		return
	}

	crawl, err := a.spider.Crawl(r.Context(), body.Seed, optsOrDefault(body.Options))
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}

	profile := a.resolveProfile(body.Profile)

	var templates []*scan.RequestTemplate
	for _, u := range crawl.URLs {
		parsed, err := url.Parse(u)
		if err != nil {
			continue
		}
		tmpl := scan.NewRequestTemplate(http.MethodGet, parsed, "", http.Header{}, nil)
		applyProfileToHeader(r.Context(), profile, tmpl.Header)
		templates = append(templates, tmpl)
	}

	result, err := a.scanner.ScanRequests(r.Context(), projectID, templates)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"crawledPages": len(crawl.Pages),
		"scannedURLs":  len(templates),
		"tasksRun":     result.TasksRun,
		"issues":       result.Issues,
	})
}
