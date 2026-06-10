package session

import "testing"

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	s := NewStore()
	if err := s.Set(Profile{
		Name:    "admin",
		Headers: []Header{{Name: "X-Role", Value: "admin"}},
		Cookies: []Cookie{{Name: "sid", Value: "abc"}},
		Bearer:  "tok",
		CSRF:    &CSRFRule{FetchURL: "http://x/", Pattern: `token=([0-9a-f]+)`, InjectHeader: "X-CSRF"},
	}); err != nil {
		t.Fatal(err)
	}

	data, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	restored := NewStore()
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}

	p, ok := restored.Get("admin")
	if !ok {
		t.Fatal("profile missing after restore")
	}
	if p.Bearer != "tok" || len(p.Cookies) != 1 || p.Cookies[0].Value != "abc" {
		t.Errorf("profile fields not restored: %+v", p)
	}
	if p.CSRF == nil || p.CSRF.InjectHeader != "X-CSRF" {
		t.Errorf("CSRF rule not restored: %+v", p.CSRF)
	}
	// The CSRF rule must be usable (recompiled) after restore.
	if p.CSRF != nil {
		if err := p.CSRF.compile(); err != nil {
			t.Errorf("restored CSRF rule should compile: %v", err)
		}
	}
}
