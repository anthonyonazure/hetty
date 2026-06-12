package assetgraph

import "testing"

func TestUpsertFirstAndLastSeen(t *testing.T) {
	g := New()
	g.Upsert(Asset{Key: "host:a.com", Kind: KindHost, Value: "a.com", Sources: []string{"recon"}}, "t1")
	g.Upsert(Asset{Key: "host:a.com", Kind: KindHost, Value: "a.com", Sources: []string{"portscan"}}, "t2")

	a, ok := g.Get("host:a.com")
	if !ok {
		t.Fatal("asset missing")
	}
	if a.FirstSeen != "t1" || a.LastSeen != "t2" {
		t.Errorf("first/last seen = %s/%s, want t1/t2", a.FirstSeen, a.LastSeen)
	}
	if len(a.Sources) != 2 {
		t.Errorf("sources should union to 2, got %v", a.Sources)
	}
}

func TestIngestBuildsGraph(t *testing.T) {
	g := New()
	g.IngestSubdomain("example.com", "api.example.com", "crtsh", "t1")
	g.IngestService("api.example.com", 443, "https", "nginx", "portscan", "t1")
	g.IngestURL("api.example.com", "https://api.example.com/", []string{"nginx", "PHP"}, "fingerprint", "t1")
	g.IngestFinding("api.example.com", "Missing security headers", "low", "scanner", "t1")

	stats := g.Stats()
	if stats["domain"] != 1 || stats["host"] != 1 || stats["service"] != 1 || stats["url"] != 1 || stats["finding"] != 1 {
		t.Fatalf("unexpected stats: %v", stats)
	}

	// The host's children should include the service, url and finding.
	children := g.Related("host:api.example.com")
	kinds := map[Kind]bool{}
	for _, c := range children {
		kinds[c.Kind] = true
	}
	if !kinds[KindService] || !kinds[KindURL] || !kinds[KindFinding] || !kinds[KindDomain] {
		t.Errorf("related kinds = %v (want service+url+finding child, domain parent)", kinds)
	}

	// Tech recorded as an attribute on the URL.
	u, _ := g.Get("url:https://api.example.com/")
	if u.Attrs["technologies"] != "nginx, PHP" {
		t.Errorf("tech attr = %q", u.Attrs["technologies"])
	}
}

func TestSnapshotRestore(t *testing.T) {
	g := New()
	g.IngestService("h.com", 22, "ssh", "OpenSSH_8", "portscan", "t1")
	blob, err := g.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	g2 := New()
	if err := g2.Restore(blob); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, ok := g2.Get("service:h.com:22"); !ok {
		t.Error("service not restored")
	}
}
