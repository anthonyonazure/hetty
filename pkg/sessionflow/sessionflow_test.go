package sessionflow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func loginServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	// /login sets a session cookie and embeds a CSRF token.
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "sess-abc"})
		fmt.Fprint(w, `<html><input name="csrf" value="TOK123"></html>`)
	})

	// /submit requires the cookie and the token echoed from the macro var.
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		ck, err := r.Cookie("session")
		if err != nil || ck.Value != "sess-abc" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("token") != "TOK123" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	return httptest.NewServer(mux)
}

func TestMacroRunExtractsAndChains(t *testing.T) {
	srv := loginServer(t)
	defer srv.Close()

	m := Macro{
		Name: "login",
		Steps: []Step{
			{Method: "GET", URL: srv.URL + "/login"},
			{Method: "GET", URL: srv.URL + "/submit?token={{csrf}}"},
		},
		Extractors: []Extractor{
			{Name: "session", Source: "cookie", Key: "session"},
			{Name: "csrf", Source: "body", Pattern: `name="csrf" value="([^"]+)"`},
		},
	}

	res, err := New().Run(context.Background(), m)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	if res.Vars["csrf"] != "TOK123" {
		t.Errorf("csrf var = %q, want TOK123", res.Vars["csrf"])
	}
	if res.Vars["session"] != "sess-abc" {
		t.Errorf("session var = %q, want sess-abc", res.Vars["session"])
	}

	// The second step must have authenticated (cookie jar + {{csrf}} substitution).
	if len(res.Steps) != 2 || res.Steps[1].Status != http.StatusOK {
		t.Fatalf("submit step status = %d, want 200 (steps=%+v)", res.Steps[1].Status, res.Steps)
	}

	// Cookie jar surfaced.
	foundCookie := false
	for _, c := range res.Cookies {
		if c.Name == "session" && c.Value == "sess-abc" {
			foundCookie = true
		}
	}
	if !foundCookie {
		t.Errorf("expected session cookie in result, got %+v", res.Cookies)
	}
}

func TestHeaderExtractorWithPattern(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Authorization", "Bearer xyz.token.here")
		w.WriteHeader(200)
	}))
	defer srv.Close()

	m := Macro{
		Name:  "hdr",
		Steps: []Step{{Method: "GET", URL: srv.URL + "/"}},
		Extractors: []Extractor{
			{Name: "bearer", Source: "header", Key: "Authorization", Pattern: `Bearer (.+)`},
		},
	}
	res, err := New().Run(context.Background(), m)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Vars["bearer"] != "xyz.token.here" {
		t.Errorf("bearer = %q, want xyz.token.here", res.Vars["bearer"])
	}
}

func TestStoreSnapshotRestore(t *testing.T) {
	s := NewStore()
	if err := s.Set(Macro{Name: "m1", Steps: []Step{{URL: "https://x/"}}}); err != nil {
		t.Fatalf("set: %v", err)
	}
	blob, err := s.Snapshot()
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	s2 := NewStore()
	if err := s2.Restore(blob); err != nil {
		t.Fatalf("restore: %v", err)
	}
	if _, ok := s2.Get("m1"); !ok {
		t.Error("macro m1 not restored")
	}
}

func TestEmptyMacroErrors(t *testing.T) {
	if _, err := New().Run(context.Background(), Macro{Name: "empty"}); err == nil {
		t.Fatal("expected error for macro with no steps")
	}
}
