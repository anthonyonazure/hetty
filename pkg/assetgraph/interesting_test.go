package assetgraph

import "testing"

func TestInterestingHeuristics(t *testing.T) {
	g := New()
	g.IngestHost("admin.example.com", "recon", "t1")
	g.IngestHost("www.example.com", "recon", "t1")
	g.IngestService("db.example.com", 3306, "mysql", "", "portscan", "t1")
	g.IngestService("web.example.com", 443, "https", "", "portscan", "t1")
	g.IngestFinding("app.example.com", "RCE via upload", "critical", "scanner", "t1")
	g.IngestFinding("app.example.com", "Info leak", "info", "scanner", "t1")

	flagged := g.Interesting()
	values := map[string]bool{}
	for _, f := range flagged {
		values[f.Value] = true
		if len(f.Reasons) == 0 {
			t.Errorf("%s flagged with no reasons", f.Value)
		}
	}

	if !values["admin.example.com"] {
		t.Error("admin host should be interesting")
	}
	if !values["db.example.com:3306"] {
		t.Error("exposed MySQL should be interesting")
	}
	if !values["RCE via upload"] {
		t.Error("critical finding should be interesting")
	}
	if values["www.example.com"] {
		t.Error("plain www host should NOT be interesting")
	}
	if values["web.example.com:443"] {
		t.Error("https on 443 should NOT be interesting")
	}
	if values["Info leak"] {
		t.Error("info finding should NOT be interesting")
	}
}
