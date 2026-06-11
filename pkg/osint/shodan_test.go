package osint

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestShodanHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.URL.Path, "/shodan/host/8.8.8.8") {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.URL.Query().Get("key") != "testkey" {
			t.Errorf("missing api key")
		}
		fmt.Fprint(w, `{
			"ip_str": "8.8.8.8",
			"org": "Google LLC",
			"os": null,
			"hostnames": ["dns.google"],
			"ports": [53, 443],
			"vulns": ["CVE-2021-1234"],
			"data": [
				{"port": 443, "transport": "tcp", "product": "nginx", "version": "1.18.0"}
			]
		}`)
	}))
	defer srv.Close()

	c := New("testkey")
	c.SetBaseURL(srv.URL)

	host, err := c.Host(context.Background(), "8.8.8.8")
	if err != nil {
		t.Fatalf("Host: %v", err)
	}
	if host.IP != "8.8.8.8" || host.Org != "Google LLC" {
		t.Errorf("unexpected host: %+v", host)
	}
	if len(host.Ports) != 2 || len(host.Vulns) != 1 || host.Vulns[0] != "CVE-2021-1234" {
		t.Errorf("ports/vulns wrong: %+v", host)
	}
	if len(host.Services) != 1 || host.Services[0].Product != "nginx" {
		t.Errorf("services wrong: %+v", host.Services)
	}
}

func TestShodanDisabled(t *testing.T) {
	c := New("")
	if c.Enabled() {
		t.Fatal("empty key should be disabled")
	}
	if _, err := c.Host(context.Background(), "1.1.1.1"); err == nil {
		t.Fatal("expected error when disabled")
	}
}

func TestShodanError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error": "Invalid API key"}`)
	}))
	defer srv.Close()

	c := New("bad")
	c.SetBaseURL(srv.URL)
	_, err := c.Host(context.Background(), "1.1.1.1")
	if err == nil || !strings.Contains(err.Error(), "Invalid API key") {
		t.Fatalf("expected invalid-key error, got %v", err)
	}
}
