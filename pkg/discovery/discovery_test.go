package discovery

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDiscoverFindsKnownPaths(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin area"))
	})
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("api root"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r) // everything else is a hard 404
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	e := New()
	res, err := e.Discover(context.Background(), srv.URL, Options{
		Wordlist:    []string{"admin", "api", "doesnotexist", "alsomissing"},
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	for _, h := range res.Hits {
		found[h.URL] = true
	}
	if !found[srv.URL+"/admin"] {
		t.Error("did not find /admin")
	}
	if !found[srv.URL+"/api"] {
		t.Error("did not find /api")
	}
	for _, h := range res.Hits {
		if strings.Contains(h.URL, "doesnotexist") || strings.Contains(h.URL, "alsomissing") {
			t.Errorf("false positive: %s", h.URL)
		}
	}
}

func TestSoft404Suppression(t *testing.T) {
	// Server returns 200 for everything (soft 404), but /real has a distinct body.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/real" {
			_, _ = w.Write([]byte("this is a genuinely real and much longer page body that differs"))
			return
		}
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	e := New()
	res, err := e.Discover(context.Background(), srv.URL, Options{
		Wordlist:    []string{"real", "fake1", "fake2", "fake3"},
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	if len(res.Hits) != 1 || !strings.HasSuffix(res.Hits[0].URL, "/real") {
		t.Errorf("soft-404 suppression failed; hits = %+v", res.Hits)
	}
}

func TestRecursion(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin dir"))
	})
	mux.HandleFunc("/admin/users", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin users list"))
	})
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("admin"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	e := New()
	res, err := e.Discover(context.Background(), srv.URL, Options{
		Wordlist:    []string{"admin", "users"},
		MaxDepth:    1,
		Concurrency: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	found := map[string]bool{}
	for _, h := range res.Hits {
		found[h.URL] = true
	}
	if !found[srv.URL+"/admin/users"] {
		t.Errorf("recursion did not find /admin/users; hits = %+v", res.Hits)
	}
}

func TestInvalidSeed(t *testing.T) {
	e := New()
	if _, err := e.Discover(context.Background(), "not-a-url", Options{}); err == nil {
		t.Error("expected error for relative seed")
	}
}
