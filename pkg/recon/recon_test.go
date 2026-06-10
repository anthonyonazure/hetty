package recon

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestEnumerateSubdomainsFromCrtsh(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[
			{"name_value": "www.example.com\napi.example.com"},
			{"name_value": "*.example.com"},
			{"name_value": "mail.example.com"},
			{"name_value": "evil.com"},
			{"name_value": "api.example.com"}
		]`))
	}))
	defer srv.Close()

	e := New()
	e.crtshBase = srv.URL
	e.lookupHost = func(ctx context.Context, host string) ([]string, error) {
		if host == "www.example.com" {
			return []string{"93.184.216.34"}, nil
		}
		return nil, &net.DNSError{Err: "no such host"}
	}

	res, err := e.EnumerateSubdomains(context.Background(), "example.com", Options{Resolve: true, Concurrency: 4})
	if err != nil {
		t.Fatal(err)
	}

	hosts := map[string]bool{}
	for _, s := range res.Subdomains {
		hosts[s.Host] = true
	}
	if !hosts["www.example.com"] || !hosts["api.example.com"] || !hosts["mail.example.com"] {
		t.Errorf("missing expected subdomains: %v", hosts)
	}
	if hosts["evil.com"] {
		t.Error("out-of-scope domain should be filtered")
	}
	// www resolved, others did not.
	if res.Resolved != 1 {
		t.Errorf("resolved = %d, want 1", res.Resolved)
	}
	// Dedup: api.example.com appears twice in input.
	count := 0
	for _, s := range res.Subdomains {
		if s.Host == "api.example.com" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("api.example.com appears %d times, want 1 (dedup failed)", count)
	}
}

func TestEnumerateInvalidDomain(t *testing.T) {
	if _, err := New().EnumerateSubdomains(context.Background(), "https://example.com/path", Options{}); err == nil {
		t.Error("expected error for non-bare domain")
	}
}

func TestFingerprint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.21.0")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		w.Header().Add("Set-Cookie", "PHPSESSID=abc; Path=/")
		_, _ = w.Write([]byte(`<html><head><title>My WP Blog</title></head><body><link href="/wp-content/themes/x/style.css"></body></html>`))
	}))
	defer srv.Close()

	e := New()
	tech, err := e.Fingerprint(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if tech.Server != "nginx/1.21.0" {
		t.Errorf("server = %q", tech.Server)
	}
	if tech.Title != "my wp blog" && !strings.EqualFold(tech.Title, "My WP Blog") {
		t.Errorf("title = %q", tech.Title)
	}

	techs := strings.Join(tech.Technologies, ",")
	for _, want := range []string{"WordPress", "nginx", "PHP"} {
		if !strings.Contains(techs, want) {
			t.Errorf("expected %q in technologies %q", want, techs)
		}
	}
}
