package ext_test

import (
	"testing"

	"github.com/dstotijn/hetty/pkg/ext"
	"github.com/dstotijn/hetty/pkg/scan"
)

type fakeHistory struct{}

func (fakeHistory) Recent(limit int) []ext.HistoryItem {
	return []ext.HistoryItem{{Method: "GET", URL: "https://a.example/x", Status: 200, ContentType: "text/html", Length: 10}}
}

type fakeSitemap struct{}

func (fakeSitemap) Entries() []ext.SitemapItem {
	return []ext.SitemapItem{{URL: "https://a.example/x", Methods: []string{"GET"}, Statuses: []int{200}, Params: []string{"q"}}}
}

type fakeCollab struct{}

func (fakeCollab) NewToken() (string, string) { return "tok123", "http://oob.example/tok123" }
func (fakeCollab) Interactions(token string) []ext.CollabItem {
	if token == "tok123" {
		return []ext.CollabItem{{Protocol: "http", RemoteAddr: "1.2.3.4", Method: "GET", Path: "/x", Time: "now"}}
	}
	return nil
}

type fakeIntruder struct {
	processors map[string]func(string) (string, error)
	generators map[string]func() ([]string, error)
}

func newFakeIntruder() *fakeIntruder {
	return &fakeIntruder{
		processors: map[string]func(string) (string, error){},
		generators: map[string]func() ([]string, error){},
	}
}
func (f *fakeIntruder) RegisterProcessor(id string, fn func(string) (string, error)) {
	f.processors[id] = fn
}
func (f *fakeIntruder) RegisterGenerator(id string, fn func() ([]string, error)) {
	f.generators[id] = fn
}

const apiExtension = `
hetty.meta({ name: "api-ext", version: "1.0.0" });

hetty.store.set("k", "v1");
hetty.store.set("k2", "v2");

hetty.registerAction({
  id: "echo",
  name: "Echo request",
  run: function(req) { return "action saw " + req.method + " " + req.url; }
});

hetty.registerPayloadProcessor({ id: "suffixer", process: function(p) { return p + "-proc"; } });
hetty.registerPayloadGenerator({ id: "list", generate: function() { return ["g1", "g2"]; } });

hetty.store.set("histCount", "" + hetty.history({ limit: 10 }).length);
hetty.store.set("siteCount", "" + hetty.sitemap().length);
var c = hetty.collab.generate();
hetty.store.set("collabToken", c.token);
hetty.store.set("collabCount", "" + hetty.collab.interactions(c.token).length);
`

func TestExtensionRichAPI(t *testing.T) {
	dir := t.TempDir()
	store := ext.NewStore()
	intr := newFakeIntruder()
	svc := scan.NewService(scan.Config{Repository: newMemRepo()})

	engine := ext.NewEngine(ext.Config{
		Dir:         dir,
		ScanService: svc,
		Store:       store,
		History:     fakeHistory{},
		Sitemap:     fakeSitemap{},
		Collab:      fakeCollab{},
		Intruder:    intr,
	})

	writeExtension(t, dir, "api.js", apiExtension)
	if _, err := engine.LoadAll(); err != nil {
		t.Fatalf("load: %v", err)
	}

	// Persistence: namespace is the file base name ("api").
	if v, ok := store.Get("api", "k"); !ok || v != "v1" {
		t.Errorf("store k = %q (%v), want v1", v, ok)
	}
	if keys := store.Keys("api"); len(keys) == 0 {
		t.Error("expected store keys for namespace api")
	}

	// history / sitemap / collab read APIs.
	if v, _ := store.Get("api", "histCount"); v != "1" {
		t.Errorf("history count = %q, want 1", v)
	}
	if v, _ := store.Get("api", "siteCount"); v != "1" {
		t.Errorf("sitemap count = %q, want 1", v)
	}
	if v, _ := store.Get("api", "collabToken"); v != "tok123" {
		t.Errorf("collab token = %q, want tok123", v)
	}
	if v, _ := store.Get("api", "collabCount"); v != "1" {
		t.Errorf("collab interactions = %q, want 1", v)
	}

	// Actions.
	actions := engine.Actions()
	if len(actions) != 1 || actions[0].ID != "ext:api-ext:echo" {
		t.Fatalf("actions = %+v, want one ext:api-ext:echo", actions)
	}
	out, err := engine.RunAction("ext:api-ext:echo", ext.ActionRequest{Method: "POST", URL: "https://t.example/p"})
	if err != nil {
		t.Fatalf("RunAction: %v", err)
	}
	if out.Output != "action saw POST https://t.example/p" {
		t.Errorf("action output = %q", out.Output)
	}

	// Intruder payload hooks registered with namespaced ids.
	proc, ok := intr.processors["ext:api-ext:suffixer"]
	if !ok {
		t.Fatal("payload processor not registered")
	}
	if v, _ := proc("abc"); v != "abc-proc" {
		t.Errorf("processor output = %q, want abc-proc", v)
	}
	gen, ok := intr.generators["ext:api-ext:list"]
	if !ok {
		t.Fatal("payload generator not registered")
	}
	vals, _ := gen()
	if len(vals) != 2 || vals[0] != "g1" || vals[1] != "g2" {
		t.Errorf("generator output = %v, want [g1 g2]", vals)
	}
}

func TestStoreSnapshotRestore(t *testing.T) {
	s := ext.NewStore()
	s.Set("ns", "a", "1")
	s.Set("ns", "b", "2")

	blob, err := s.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}

	s2 := ext.NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if v, ok := s2.Get("ns", "a"); !ok || v != "1" {
		t.Errorf("restored a = %q (%v), want 1", v, ok)
	}
	if v, ok := s2.Get("ns", "b"); !ok || v != "2" {
		t.Errorf("restored b = %q (%v), want 2", v, ok)
	}
}
