package session

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestProfileApply(t *testing.T) {
	p := Profile{
		Name:    "admin",
		Headers: []Header{{Name: "X-Role", Value: "admin"}},
		Cookies: []Cookie{{Name: "sid", Value: "abc"}, {Name: "csrf", Value: "xyz"}},
		Bearer:  "tok123",
	}
	h := make(http.Header)
	h.Set("Cookie", "existing=1")
	p.Apply(h)

	if got := h.Get("X-Role"); got != "admin" {
		t.Errorf("X-Role = %q, want admin", got)
	}
	if got := h.Get("Authorization"); got != "Bearer tok123" {
		t.Errorf("Authorization = %q", got)
	}
	if got := h.Get("Cookie"); got != "existing=1; sid=abc; csrf=xyz" {
		t.Errorf("Cookie = %q", got)
	}
}

func TestStripped(t *testing.T) {
	h := make(http.Header)
	h.Set("Authorization", "Bearer x")
	h.Set("Cookie", "sid=1")
	h.Set("Accept", "application/json")
	out := Stripped(h)
	if out.Get("Authorization") != "" || out.Get("Cookie") != "" {
		t.Error("identity headers not stripped")
	}
	if out.Get("Accept") != "application/json" {
		t.Error("non-identity header should be preserved")
	}
}

func TestStoreCRUD(t *testing.T) {
	s := NewStore()
	if err := s.Set(Profile{Name: "u1"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Set(Profile{Name: ""}); err == nil {
		t.Error("expected error for empty name")
	}
	if _, ok := s.Get("u1"); !ok {
		t.Error("u1 not found")
	}
	if len(s.List()) != 1 {
		t.Errorf("List len = %d, want 1", len(s.List()))
	}
	s.Delete("u1")
	if _, ok := s.Get("u1"); ok {
		t.Error("u1 should be deleted")
	}
}

func TestCSRFResolve(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<input name="csrf_token" value="TOKEN-42">`))
	}))
	defer srv.Close()

	rule := &CSRFRule{
		FetchURL:     srv.URL,
		Pattern:      `name="csrf_token" value="([^"]+)"`,
		InjectHeader: "X-CSRF-Token",
	}
	tok, err := rule.Resolve(context.Background(), srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	if tok != "TOKEN-42" {
		t.Errorf("token = %q, want TOKEN-42", tok)
	}
}

func TestCSRFInvalidPattern(t *testing.T) {
	s := NewStore()
	err := s.Set(Profile{Name: "p", CSRF: &CSRFRule{Pattern: "nogroup"}})
	if err == nil {
		t.Error("expected error: pattern without capture group")
	}
}
