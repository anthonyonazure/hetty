package sitemap

import "testing"

func TestSnapshotRestoreRoundTrip(t *testing.T) {
	s := New()
	s.Add(Entry{URL: "https://ex.com/api/users?id=1", Method: "GET", Status: 200, ContentType: "application/json", Server: "nginx", Source: "proxy"})
	s.Add(Entry{URL: "https://ex.com/api/users", Method: "POST", Status: 201, Source: "spider"})
	s.Add(Entry{URL: "https://ex.com/admin", Method: "GET", Status: 403, Powered: "PHP/8.1"})

	data, err := s.Snapshot()
	if err != nil {
		t.Fatal(err)
	}

	restored := New()
	if err := restored.Restore(data); err != nil {
		t.Fatal(err)
	}

	orig := s.Tree()
	got := restored.Tree()

	if len(got.Hosts) != len(orig.Hosts) {
		t.Fatalf("host count after restore = %d, want %d", len(got.Hosts), len(orig.Hosts))
	}

	users := findChild(findChild(got.Hosts[0], "api"), "users")
	if users == nil {
		t.Fatal("api/users missing after restore")
	}
	if len(users.Methods) != 2 {
		t.Errorf("methods after restore = %v, want GET+POST", users.Methods)
	}
	if len(users.Statuses) != 2 {
		t.Errorf("statuses after restore = %v, want 200+201", users.Statuses)
	}
	if !contains(users.Params, "id") {
		t.Errorf("params after restore = %v, want id", users.Params)
	}

	if len(got.Tech) == 0 || !contains(got.Tech[0].Servers, "nginx") {
		t.Errorf("tech not restored: %+v", got.Tech)
	}

	// Restored store must keep aggregating new observations correctly.
	restored.Add(Entry{URL: "https://ex.com/api/users", Method: "DELETE", Status: 204})
	users2 := findChild(findChild(restored.Tree().Hosts[0], "api"), "users")
	if len(users2.Methods) != 3 {
		t.Errorf("after restore+add, methods = %v, want GET+POST+DELETE", users2.Methods)
	}
}

func TestRestoreEmpty(t *testing.T) {
	s := New()
	if err := s.Restore(nil); err != nil {
		t.Errorf("restore of nil should be a no-op, got %v", err)
	}
	if s.HostCount() != 0 {
		t.Error("restore of nil should leave store empty")
	}
}
