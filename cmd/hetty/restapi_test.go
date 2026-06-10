package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/dstotijn/hetty/pkg/collab"
	"github.com/dstotijn/hetty/pkg/db/bolt"
	"github.com/dstotijn/hetty/pkg/ext"
	"github.com/dstotijn/hetty/pkg/intruder"
	"github.com/dstotijn/hetty/pkg/proj"
	"github.com/dstotijn/hetty/pkg/proxy/intercept"
	"github.com/dstotijn/hetty/pkg/reqlog"
	"github.com/dstotijn/hetty/pkg/rules"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/scope"
	"github.com/dstotijn/hetty/pkg/sender"
	"github.com/dstotijn/hetty/pkg/session"
	"github.com/dstotijn/hetty/pkg/spider"
)

func vulnTarget() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "VulnServer/1.0")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.URL.Query().Get("q"))
	})
	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "a=%s", r.URL.Query().Get("a"))
	})
	return httptest.NewServer(mux)
}

func setupAPI(t *testing.T) (*httptest.Server, func()) {
	t.Helper()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	boltDB, err := bolt.OpenDatabase(dbPath, nil)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}

	sc := &scope.Scope{}
	reqLogSvc := reqlog.NewService(reqlog.Config{Scope: sc, Repository: boltDB})
	interceptSvc := intercept.NewService(intercept.Config{})
	senderSvc := sender.NewService(sender.Config{Repository: boltDB, ReqLogService: reqLogSvc})

	opts := scan.DefaultOptions()
	opts.RequestTimeout = 10 * time.Second
	opts.PassiveOnProxy = false
	scanSvc := scan.NewService(scan.Config{Repository: boltDB, Options: opts})

	projSvc, err := proj.NewService(proj.Config{
		Repository:       boltDB,
		InterceptService: interceptSvc,
		ReqLogService:    reqLogSvc,
		SenderService:    senderSvc,
		Scope:            sc,
		ScanService:      scanSvc,
	})
	if err != nil {
		t.Fatalf("proj svc: %v", err)
	}

	rulesEngine := rules.NewEngine()
	intruderEngine := intruder.NewEngine()
	collabSrv := collab.NewServer("http://placeholder")
	extEngine := ext.NewEngine(ext.Config{Dir: t.TempDir(), ScanService: scanSvc})
	if _, err := extEngine.LoadAll(); err != nil {
		t.Fatalf("ext load: %v", err)
	}

	ctx := context.Background()
	p, err := projSvc.CreateProject(ctx, "test")
	if err != nil {
		t.Fatalf("create project: %v", err)
	}
	if _, err := projSvc.OpenProject(ctx, p.ID); err != nil {
		t.Fatalf("open project: %v", err)
	}

	api := &restAPI{
		scanner:  scanSvc,
		intruder: intruderEngine,
		rules:    rulesEngine,
		ext:      extEngine,
		collab:   collabSrv,
		proj:     projSvc,
		spider:   spider.New(),
		sessions: session.NewStore(),
	}

	srv := httptest.NewServer(api.Handler())
	return srv, func() { srv.Close(); boltDB.Close() }
}

func doReq(t *testing.T, base, method, path string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, base+path, rdr)
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer res.Body.Close()
	var out map[string]interface{}
	json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestRESTDecoder(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()

	status, out := doReq(t, srv.URL, "POST", "/api/decoder", map[string]string{"codec": "base64", "op": "encode", "input": "abc"})
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if out["output"] != "YWJj" {
		t.Errorf("base64 encode = %v, want YWJj", out["output"])
	}

	status, out = doReq(t, srv.URL, "GET", "/api/decoder/codecs", nil)
	if status != 200 || out["codecs"] == nil {
		t.Errorf("codecs list failed: %d %v", status, out)
	}
}

func TestRESTSequencer(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	status, out := doReq(t, srv.URL, "POST", "/api/sequencer", map[string]interface{}{"tokens": []string{"AAAA", "AAAA", "AAAA"}})
	if status != 200 {
		t.Fatalf("status %d", status)
	}
	if out["quality"] != "poor" {
		t.Errorf("quality = %v, want poor", out["quality"])
	}
}

func TestRESTComparer(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	status, out := doReq(t, srv.URL, "POST", "/api/comparer", map[string]string{"a": "admin=false", "b": "admin=true", "mode": "words"})
	if status != 200 || out["segments"] == nil {
		t.Errorf("comparer failed: %d %v", status, out)
	}
}

func TestRESTRules(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	rule := map[string]interface{}{"id": "x", "name": "x", "enabled": true, "part": "request_body", "match": "a", "replace": "b"}
	status, out := doReq(t, srv.URL, "PUT", "/api/rules", map[string]interface{}{"rules": []interface{}{rule}})
	if status != 200 {
		t.Fatalf("put rules status %d: %v", status, out)
	}
	status, out = doReq(t, srv.URL, "GET", "/api/rules", nil)
	if status != 200 {
		t.Fatalf("get rules status %d", status)
	}
	rl, _ := out["rules"].([]interface{})
	if len(rl) != 1 {
		t.Errorf("rules len = %d, want 1", len(rl))
	}
}

func TestRESTIntruder(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	target := vulnTarget()
	defer target.Close()

	status, out := doReq(t, srv.URL, "POST", "/api/intruder/positions", map[string]interface{}{
		"base": map[string]interface{}{"method": "GET", "url": "http://x/?a=" + "§p§"},
	})
	if status != 200 || out["positions"].(float64) != 1 {
		t.Errorf("positions = %v (status %d)", out["positions"], status)
	}

	attack := map[string]interface{}{
		"type":        "sniper",
		"base":        map[string]interface{}{"method": "GET", "url": target.URL + "/echo?a=" + "§p§"},
		"payloadSets": []interface{}{[]interface{}{"1", "2", "3"}},
	}
	status, out = doReq(t, srv.URL, "POST", "/api/intruder/run", attack)
	if status != 200 {
		t.Fatalf("intruder run status %d: %v", status, out)
	}
	results, _ := out["results"].([]interface{})
	if len(results) != 3 {
		t.Errorf("intruder results = %d, want 3", len(results))
	}
}

func TestRESTCollab(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	status, out := doReq(t, srv.URL, "POST", "/api/collab/token", nil)
	if status != 200 || out["token"] == nil || out["url"] == nil {
		t.Fatalf("collab token failed: %d %v", status, out)
	}
}

func TestRESTExtensions(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	status, out := doReq(t, srv.URL, "GET", "/api/extensions", nil)
	if status != 200 {
		t.Fatalf("extensions status %d", status)
	}
	if _, ok := out["extensions"]; !ok {
		t.Errorf("missing extensions key: %v", out)
	}
}

func TestRESTScanner(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	target := vulnTarget()
	defer target.Close()

	old := scan.CmdInjectionDelaySeconds
	scan.CmdInjectionDelaySeconds = 2
	defer func() { scan.CmdInjectionDelaySeconds = old }()

	status, out := doReq(t, srv.URL, "POST", "/api/scanner/scan", map[string]string{
		"method": "GET", "url": target.URL + "/reflect?q=hi",
	})
	if status != 200 {
		t.Fatalf("scan status %d: %v", status, out)
	}
	issues, _ := out["issues"].([]interface{})
	found := false
	for _, it := range issues {
		m := it.(map[string]interface{})
		if m["checkId"] == "xss-reflected" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected xss-reflected issue; got %v", out["issues"])
	}

	status, out = doReq(t, srv.URL, "GET", "/api/scanner/issues", nil)
	if status != 200 {
		t.Fatalf("list issues status %d", status)
	}
	if il, _ := out["issues"].([]interface{}); len(il) == 0 {
		t.Errorf("expected persisted issues")
	}

	status, _ = doReq(t, srv.URL, "GET", "/api/scanner/checks", nil)
	if status != 200 {
		t.Errorf("checks status %d", status)
	}

	status, _ = doReq(t, srv.URL, "DELETE", "/api/scanner/issues", nil)
	if status != 200 {
		t.Errorf("clear status %d", status)
	}
}

func linkedTarget() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/page1?id=1">1</a> <a href="/page2">2</a></body></html>`)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>p1</body></html>")
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, "<html><body>p2</body></html>")
	})
	return httptest.NewServer(mux)
}

func TestRESTSpiderCrawl(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	target := linkedTarget()
	defer target.Close()

	status, out := doReq(t, srv.URL, "POST", "/api/spider/crawl", map[string]interface{}{
		"seed":    target.URL + "/",
		"options": map[string]interface{}{"maxDepth": 2, "maxPages": 50, "sameHostOnly": true},
	})
	if status != 200 {
		t.Fatalf("crawl status %d: %v", status, out)
	}
	urls, _ := out["urls"].([]interface{})
	if len(urls) < 3 {
		t.Errorf("expected >=3 crawled urls, got %d (%v)", len(urls), urls)
	}
}

// headerRecorder captures the headers of every request a target receives, so a
// test can assert that an auth profile was actually applied to outgoing
// scanner/intruder requests.
type headerRecorder struct {
	mu      sync.Mutex
	headers []http.Header
}

func (rc *headerRecorder) add(h http.Header) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	rc.headers = append(rc.headers, h.Clone())
}

func (rc *headerRecorder) sawHeader(name, value string) bool {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	for _, h := range rc.headers {
		if h.Get(name) == value {
			return true
		}
	}
	return false
}

func recordingTarget(rc *headerRecorder) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		rc.add(r.Header)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>%s</body></html>", r.URL.Query().Get("q"))
	})
	return httptest.NewServer(mux)
}

func TestRESTProfileInjection(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()

	rc := &headerRecorder{}
	target := recordingTarget(rc)
	defer target.Close()

	// Create an auth profile carrying a cookie and an identity header.
	profile := map[string]interface{}{
		"name":    "alice",
		"cookies": []map[string]string{{"name": "sid", "value": "alicesid"}},
		"headers": []map[string]string{{"name": "X-Identity", "value": "alice"}},
	}
	status, _ := doReq(t, srv.URL, "PUT", "/api/session/profiles", profile)
	if status != 200 {
		t.Fatalf("create profile status %d", status)
	}

	// Intruder run with the profile applied.
	attack := map[string]interface{}{
		"type":        "sniper",
		"base":        map[string]interface{}{"method": "GET", "url": target.URL + "/?q=" + "§p§"},
		"payloadSets": []interface{}{[]interface{}{"x"}},
		"profile":     "alice",
	}
	status, out := doReq(t, srv.URL, "POST", "/api/intruder/run", attack)
	if status != 200 {
		t.Fatalf("intruder run status %d: %v", status, out)
	}
	if !rc.sawHeader("Cookie", "sid=alicesid") {
		t.Error("intruder request did not carry the profile cookie")
	}
	if !rc.sawHeader("X-Identity", "alice") {
		t.Error("intruder request did not carry the profile identity header")
	}

	// Scanner run with the profile applied.
	rc.mu.Lock()
	rc.headers = nil
	rc.mu.Unlock()

	status, out = doReq(t, srv.URL, "POST", "/api/scanner/scan", map[string]string{
		"method": "GET", "url": target.URL + "/?q=hi", "profile": "alice",
	})
	if status != 200 {
		t.Fatalf("scan status %d: %v", status, out)
	}
	if !rc.sawHeader("Cookie", "sid=alicesid") {
		t.Error("scanner request did not carry the profile cookie")
	}
	if !rc.sawHeader("X-Identity", "alice") {
		t.Error("scanner request did not carry the profile identity header")
	}
}

func TestRESTCrawlScan(t *testing.T) {
	srv, done := setupAPI(t)
	defer done()
	target := linkedTarget()
	defer target.Close()

	old := scan.CmdInjectionDelaySeconds
	scan.CmdInjectionDelaySeconds = 2
	defer func() { scan.CmdInjectionDelaySeconds = old }()

	status, out := doReq(t, srv.URL, "POST", "/api/scanner/crawl-scan", map[string]interface{}{
		"seed":    target.URL + "/",
		"options": map[string]interface{}{"maxDepth": 1, "maxPages": 10, "sameHostOnly": true},
	})
	if status != 200 {
		t.Fatalf("crawl-scan status %d: %v", status, out)
	}
	if out["scannedURLs"].(float64) < 1 {
		t.Errorf("expected scannedURLs >= 1, got %v", out["scannedURLs"])
	}
}
