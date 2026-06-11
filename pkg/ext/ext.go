// Package ext implements Hetty's extension ecosystem. Extensions are plain
// JavaScript files loaded from a directory and executed in an embedded,
// pure-Go ECMAScript runtime (goja). They interact with Hetty through the
// `hetty` host API: logging, sending HTTP requests, hooking proxied
// request/response traffic, and registering custom active/passive scan checks.
package ext

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/dop251/goja"

	"github.com/dstotijn/hetty/pkg/log"
	"github.com/dstotijn/hetty/pkg/proxy"
	"github.com/dstotijn/hetty/pkg/scan"
)

// Config configures the extension Engine.
type Config struct {
	// Dir is the directory scanned for `*.js` extension files.
	Dir string
	// ScanService receives custom checks and raised issues. May be nil, in
	// which case check registration and raiseIssue are no-ops.
	ScanService *scan.Service
	// Logger is used for extension logging and load diagnostics.
	Logger log.Logger
	// HTTPClient is used by hetty.send(). Defaults to http.DefaultClient.
	HTTPClient *http.Client

	// Store backs hetty.store (persistence). May be nil to disable it.
	Store *Store
	// History backs hetty.history(). May be nil.
	History HistoryProvider
	// Sitemap backs hetty.sitemap(). May be nil.
	Sitemap SitemapProvider
	// Collab backs hetty.collab. May be nil.
	Collab CollabProvider
	// Intruder backs hetty.registerPayloadGenerator/Processor. May be nil.
	Intruder PayloadRegistry
}

// Engine loads and manages JavaScript extensions.
type Engine struct {
	dir        string
	scan       *scan.Service
	logger     log.Logger
	httpClient *http.Client

	store    *Store
	history  HistoryProvider
	sitemap  SitemapProvider
	collab   CollabProvider
	intruder PayloadRegistry

	mu   sync.RWMutex
	exts []*Extension
}

// NewEngine returns a new, empty Engine. Call LoadAll to load extensions.
func NewEngine(cfg Config) *Engine {
	e := &Engine{
		dir:        cfg.Dir,
		scan:       cfg.ScanService,
		logger:     cfg.Logger,
		httpClient: cfg.HTTPClient,
		store:      cfg.Store,
		history:    cfg.History,
		sitemap:    cfg.Sitemap,
		collab:     cfg.Collab,
		intruder:   cfg.Intruder,
	}

	if e.logger == nil {
		e.logger = log.NewNopLogger()
	}

	if e.httpClient == nil {
		e.httpClient = http.DefaultClient
	}

	return e
}

// Actions returns all send-to/context actions registered by loaded extensions.
func (e *Engine) Actions() []ActionInfo {
	exts := e.snapshot()
	var out []ActionInfo
	for _, ext := range exts {
		for _, a := range ext.actions {
			out = append(out, ActionInfo{
				ID:   "ext:" + ext.name + ":" + a.id,
				Name: a.name,
				Ext:  ext.name,
			})
		}
	}
	return out
}

// RunAction invokes the action with the given full id (ext:<name>:<id>),
// passing it the request and returning its textual result.
func (e *Engine) RunAction(fullID string, req ActionRequest) (ActionResult, error) {
	exts := e.snapshot()
	for _, ext := range exts {
		for _, a := range ext.actions {
			if "ext:"+ext.name+":"+a.id == fullID {
				return ext.runAction(a, req)
			}
		}
	}
	return ActionResult{}, fmt.Errorf("ext: unknown action %q", fullID)
}

// Info is a serializable summary of a loaded extension.
type Info struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	Description   string `json:"description"`
	Path          string `json:"path"`
	RequestHooks  int    `json:"requestHooks"`
	ResponseHooks int    `json:"responseHooks"`
	ActiveChecks  int    `json:"activeChecks"`
	PassiveChecks int    `json:"passiveChecks"`
	Error         string `json:"error,omitempty"`
}

// LoadAll loads (or reloads) every `*.js` file in the configured directory. It
// returns the per-extension load results. A failure to load one extension does
// not abort the others.
func (e *Engine) LoadAll() ([]Info, error) {
	if e.dir == "" {
		return nil, nil
	}

	if err := os.MkdirAll(e.dir, 0o755); err != nil {
		return nil, fmt.Errorf("ext: failed to create extensions dir: %w", err)
	}

	entries, err := os.ReadDir(e.dir)
	if err != nil {
		return nil, fmt.Errorf("ext: failed to read extensions dir: %w", err)
	}

	var (
		loaded []*Extension
		infos  []Info
	)

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".js") {
			continue
		}

		path := filepath.Join(e.dir, entry.Name())

		ext, err := e.load(path)
		if err != nil {
			e.logger.Errorw("Failed to load extension.", "path", path, "error", err)
			infos = append(infos, Info{
				Name:  strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())),
				Path:  path,
				Error: err.Error(),
			})

			continue
		}

		loaded = append(loaded, ext)
		infos = append(infos, ext.info())

		e.logger.Infow("Loaded extension.",
			"name", ext.name,
			"requestHooks", len(ext.reqHooks),
			"responseHooks", len(ext.resHooks),
			"activeChecks", len(ext.activeChecks),
			"passiveChecks", len(ext.passiveChecks))
	}

	e.mu.Lock()
	e.exts = loaded
	e.mu.Unlock()

	// Register custom checks into the scanner registry.
	if e.scan != nil {
		reg := e.scan.Registry()
		for _, ext := range loaded {
			for _, ac := range ext.activeChecks {
				reg.RegisterActive(ac)
			}
			for _, pc := range ext.passiveChecks {
				reg.RegisterPassive(pc)
			}
		}
	}

	return infos, nil
}

func (e *Engine) load(path string) (*Extension, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	ext := &Extension{
		name:    strings.TrimSuffix(filepath.Base(path), filepath.Ext(path)),
		path:    path,
		version: "0.0.0",
		vm:      goja.New(),
		engine:  e,
	}

	ext.vm.SetFieldNameMapper(goja.TagFieldNameMapper("json", true))

	installHostAPI(e, ext)

	if _, err := ext.vm.RunScript(filepath.Base(path), string(src)); err != nil {
		return nil, fmt.Errorf("eval: %w", err)
	}

	return ext, nil
}

// Extensions returns summaries of the currently loaded extensions.
func (e *Engine) Extensions() []Info {
	e.mu.RLock()
	defer e.mu.RUnlock()

	infos := make([]Info, 0, len(e.exts))
	for _, ext := range e.exts {
		infos = append(infos, ext.info())
	}

	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })

	return infos
}

// RequestModifier returns proxy middleware that runs every extension's request
// hooks. It implements proxy.RequestModifyMiddleware.
func (e *Engine) RequestModifier(next proxy.RequestModifyFunc) proxy.RequestModifyFunc {
	return func(req *http.Request) {
		next(req)
		e.applyRequestHooks(req)
	}
}

// ResponseModifier returns proxy middleware that runs every extension's
// response hooks. It implements proxy.ResponseModifyMiddleware.
func (e *Engine) ResponseModifier(next proxy.ResponseModifyFunc) proxy.ResponseModifyFunc {
	return func(res *http.Response) error {
		if err := next(res); err != nil {
			return err
		}

		e.applyResponseHooks(res)

		return nil
	}
}

func (e *Engine) snapshot() []*Extension {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]*Extension, len(e.exts))
	copy(out, e.exts)

	return out
}

func (e *Engine) applyRequestHooks(req *http.Request) {
	exts := e.snapshot()

	hasHooks := false
	for _, ext := range exts {
		if len(ext.reqHooks) > 0 {
			hasHooks = true
			break
		}
	}
	if !hasHooks {
		return
	}

	rt, err := scan.RequestTemplateFromHTTP(req)
	if err != nil {
		e.logger.Errorw("Extension request hook: failed to read request.", "error", err)
		return
	}

	changed := false
	for _, ext := range exts {
		if len(ext.reqHooks) == 0 {
			continue
		}
		if ext.runRequestHooks(rt) {
			changed = true
		}
	}

	if changed {
		applyTemplateToRequest(rt, req)
	}
}

func (e *Engine) applyResponseHooks(res *http.Response) {
	exts := e.snapshot()

	hasHooks := false
	for _, ext := range exts {
		if len(ext.resHooks) > 0 {
			hasHooks = true
			break
		}
	}
	if !hasHooks {
		return
	}

	var reqTmpl *scan.RequestTemplate
	if res.Request != nil {
		reqTmpl, _ = scan.RequestTemplateFromHTTP(res.Request)
	}

	sr, err := scan.ResponseFromHTTP(res)
	if err != nil {
		e.logger.Errorw("Extension response hook: failed to read response.", "error", err)
		return
	}

	changed := false
	for _, ext := range exts {
		if len(ext.resHooks) == 0 {
			continue
		}
		if ext.runResponseHooks(reqTmpl, sr) {
			changed = true
		}
	}

	if changed {
		applyResponseChanges(sr, res)
	}
}

func applyTemplateToRequest(rt *scan.RequestTemplate, req *http.Request) {
	if rt.Method != "" {
		req.Method = rt.Method
	}
	req.Header = rt.Header.Clone()
	req.Body = io.NopCloser(bytes.NewReader(rt.Body))
	req.ContentLength = int64(len(rt.Body))
	req.Header.Del("Content-Length")
}

func applyResponseChanges(sr *scan.Response, res *http.Response) {
	res.Header = sr.Header.Clone()
	res.StatusCode = sr.StatusCode
	res.Body = io.NopCloser(bytes.NewReader(sr.Body))
	res.ContentLength = int64(len(sr.Body))
	res.Header.Set("Content-Length", fmt.Sprintf("%d", len(sr.Body)))
}

// recordIssue stores an extension-raised issue under the active project.
func (e *Engine) recordIssue(checkID string, base *scan.RequestTemplate, f scan.Finding) {
	if e.scan == nil {
		return
	}

	projectID := e.scan.ActiveProjectID()
	if (projectID.Compare(zeroULID)) == 0 {
		return
	}

	if _, err := e.scan.AddIssue(context.Background(), projectID, checkID, base, nil, f); err != nil {
		e.logger.Errorw("Extension failed to raise issue.", "check", checkID, "error", err)
	}
}
