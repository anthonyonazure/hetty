package ext_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/oklog/ulid"

	"github.com/dstotijn/hetty/pkg/ext"
	"github.com/dstotijn/hetty/pkg/scan"
)

type memRepo struct {
	mu     sync.Mutex
	issues map[ulid.ULID][]scan.Issue
}

func newMemRepo() *memRepo { return &memRepo{issues: map[ulid.ULID][]scan.Issue{}} }

func (r *memRepo) StoreIssue(_ context.Context, i scan.Issue) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.issues[i.ProjectID] = append(r.issues[i.ProjectID], i)
	return nil
}

func (r *memRepo) FindIssues(_ context.Context, p ulid.ULID) ([]scan.Issue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]scan.Issue, len(r.issues[p]))
	copy(out, r.issues[p])
	return out, nil
}

func (r *memRepo) FindIssueByID(_ context.Context, p, id ulid.ULID) (scan.Issue, error) {
	return scan.Issue{}, nil
}

func (r *memRepo) ClearIssues(_ context.Context, p ulid.ULID) error { return nil }

const testExtension = `
hetty.meta({ name: "test-ext", version: "1.0.0", description: "test" });

hetty.on("request", function(req) {
    req.headers["X-Hetty-Ext"] = "1";
});

hetty.on("response", function(res, req) {
    res.headers["X-Scanned-By"] = "hetty-ext";
});

hetty.registerPassiveCheck({
    id: "secret-finder",
    name: "Secret in response",
    run: function(req, res) {
        if (res.body.indexOf("SECRET") !== -1) {
            return { name: "Secret leak", severity: "high", confidence: "firm", evidence: "found SECRET" };
        }
        return null;
    }
});

hetty.registerActiveCheck({
    id: "marker",
    name: "Marker check",
    payloads: ["AAA", "BBB"],
    detect: function(payload, res, baseline) { return null; }
});
`

func writeExtension(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write extension: %v", err)
	}
}

func newEngine(t *testing.T) (*ext.Engine, *scan.Service, ulid.ULID, string) {
	t.Helper()

	dir := t.TempDir()
	svc := scan.NewService(scan.Config{Repository: newMemRepo()})

	entropy := ulid.Monotonic(constReader{}, 0)
	pid := ulid.MustNew(ulid.Now(), entropy)
	svc.SetActiveProjectID(pid)

	engine := ext.NewEngine(ext.Config{Dir: dir, ScanService: svc})

	return engine, svc, pid, dir
}

type constReader struct{}

func (constReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i * 3)
	}
	return len(p), nil
}

func TestLoadAndIntrospect(t *testing.T) {
	engine, _, _, dir := newEngine(t)
	writeExtension(t, dir, "test.js", testExtension)

	infos, err := engine.LoadAll()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(infos) != 1 {
		t.Fatalf("loaded %d extensions, want 1", len(infos))
	}

	info := infos[0]
	if info.Name != "test-ext" {
		t.Errorf("name = %q, want test-ext (from hetty.meta)", info.Name)
	}
	if info.RequestHooks != 1 || info.ResponseHooks != 1 {
		t.Errorf("hooks = req:%d res:%d, want 1/1", info.RequestHooks, info.ResponseHooks)
	}
	if info.PassiveChecks != 1 || info.ActiveChecks != 1 {
		t.Errorf("checks = active:%d passive:%d, want 1/1", info.ActiveChecks, info.PassiveChecks)
	}
}

func TestPassiveCheckFromExtension(t *testing.T) {
	engine, svc, pid, dir := newEngine(t)
	writeExtension(t, dir, "test.js", testExtension)

	if _, err := engine.LoadAll(); err != nil {
		t.Fatalf("load: %v", err)
	}

	u, _ := url.Parse("https://example.com/")
	req := scan.NewRequestTemplate(http.MethodGet, u, "HTTP/1.1", http.Header{}, nil)
	res := &scan.Response{StatusCode: 200, Header: http.Header{}, Body: []byte("here is a SECRET token")}

	issues, err := svc.PassiveScan(context.Background(), pid, req, res)
	if err != nil {
		t.Fatalf("passive scan: %v", err)
	}

	found := false
	for _, iss := range issues {
		if iss.CheckID == "ext:test-ext:secret-finder" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected ext passive check to fire; got %d issues", len(issues))
	}
}

func TestRequestHookModifiesRequest(t *testing.T) {
	engine, _, _, dir := newEngine(t)
	writeExtension(t, dir, "test.js", testExtension)

	if _, err := engine.LoadAll(); err != nil {
		t.Fatalf("load: %v", err)
	}

	// Build the modifier chain: terminal nop wrapped by the engine modifier.
	nop := func(_ *http.Request) {}
	modifier := engine.RequestModifier(nop)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	modifier(req)

	if got := req.Header.Get("X-Hetty-Ext"); got != "1" {
		t.Errorf("X-Hetty-Ext = %q, want 1 (request hook should have set it)", got)
	}
}

func TestResponseHookModifiesResponse(t *testing.T) {
	engine, _, _, dir := newEngine(t)
	writeExtension(t, dir, "test.js", testExtension)

	if _, err := engine.LoadAll(); err != nil {
		t.Fatalf("load: %v", err)
	}

	nop := func(_ *http.Response) error { return nil }
	modifier := engine.ResponseModifier(nop)

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	res := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       http.NoBody,
		Request:    req,
	}

	if err := modifier(res); err != nil {
		t.Fatalf("modifier: %v", err)
	}

	if got := res.Header.Get("X-Scanned-By"); got != "hetty-ext" {
		t.Errorf("X-Scanned-By = %q, want hetty-ext", got)
	}
}

func TestExampleExtensionsLoad(t *testing.T) {
	dir := filepath.Join("..", "..", "examples", "extensions")
	if _, err := os.Stat(dir); err != nil {
		t.Skipf("examples dir not present: %v", err)
	}

	svc := scan.NewService(scan.Config{Repository: newMemRepo()})
	engine := ext.NewEngine(ext.Config{Dir: dir, ScanService: svc})

	infos, err := engine.LoadAll()
	if err != nil {
		t.Fatalf("load examples: %v", err)
	}
	if len(infos) < 3 {
		t.Fatalf("expected >=3 example extensions, got %d", len(infos))
	}
	for _, info := range infos {
		if info.Error != "" {
			t.Errorf("example %q failed to load: %s", info.Name, info.Error)
		}
	}

	// The example set must register at least one active and one passive check.
	reg := svc.Registry()
	activeFromExt, passiveFromExt := 0, 0
	for _, c := range reg.ActiveChecks() {
		if len(c.ID()) > 4 && c.ID()[:4] == "ext:" {
			activeFromExt++
		}
	}
	for _, c := range reg.PassiveChecks() {
		if len(c.ID()) > 4 && c.ID()[:4] == "ext:" {
			passiveFromExt++
		}
	}
	if activeFromExt < 1 {
		t.Errorf("expected an example active check to register")
	}
	if passiveFromExt < 1 {
		t.Errorf("expected an example passive check to register")
	}
}
