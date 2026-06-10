package sitemap

import "testing"

func TestAddAndTree(t *testing.T) {
	s := New()
	s.Add(Entry{URL: "https://ex.com/api/users?id=1", Method: "GET", Status: 200, ContentType: "application/json", Server: "nginx", Source: "proxy"})
	s.Add(Entry{URL: "https://ex.com/api/users", Method: "POST", Status: 201, Source: "proxy"})
	s.Add(Entry{URL: "https://ex.com/admin", Method: "GET", Status: 403, Powered: "PHP/8.1", Source: "spider"})

	tree := s.Tree()
	if len(tree.Hosts) != 1 {
		t.Fatalf("hosts = %d, want 1", len(tree.Hosts))
	}
	host := tree.Hosts[0]
	if host.Name != "ex.com" {
		t.Errorf("host name = %q", host.Name)
	}

	// api/users node should merge GET+POST and statuses 200+201.
	api := findChild(host, "api")
	if api == nil {
		t.Fatal("api node missing")
	}
	users := findChild(api, "users")
	if users == nil {
		t.Fatal("users node missing")
	}
	if len(users.Methods) != 2 {
		t.Errorf("users methods = %v, want GET+POST", users.Methods)
	}
	if len(users.Statuses) != 2 {
		t.Errorf("users statuses = %v, want 200+201", users.Statuses)
	}
	if !contains(users.Params, "id") {
		t.Errorf("users params = %v, want id", users.Params)
	}

	// Tech detection.
	if len(tree.Tech) != 1 {
		t.Fatalf("tech entries = %d", len(tree.Tech))
	}
	if !contains(tree.Tech[0].Servers, "nginx") {
		t.Errorf("servers = %v, want nginx", tree.Tech[0].Servers)
	}
	if !contains(tree.Tech[0].Powered, "PHP/8.1") {
		t.Errorf("powered = %v, want PHP/8.1", tree.Tech[0].Powered)
	}
}

func TestClear(t *testing.T) {
	s := New()
	s.Add(Entry{URL: "https://ex.com/a", Method: "GET", Status: 200})
	if s.HostCount() != 1 {
		t.Fatal("expected 1 host")
	}
	s.Clear()
	if s.HostCount() != 0 {
		t.Error("expected 0 hosts after clear")
	}
}

func TestIgnoresInvalidURL(t *testing.T) {
	s := New()
	s.Add(Entry{URL: "://bad", Method: "GET"})
	s.Add(Entry{URL: "/relative", Method: "GET"})
	if s.HostCount() != 0 {
		t.Errorf("invalid/relative URLs should be ignored, got %d hosts", s.HostCount())
	}
}

func findChild(n *Node, name string) *Node {
	for _, c := range n.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
