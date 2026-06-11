package tlsscan

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanTLSServer(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "https://")

	res, err := Scan(context.Background(), addr, Options{TimeoutMs: 4000, ServerName: "example.com"})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}

	// httptest serves modern TLS (1.2 and/or 1.3).
	if len(res.Protocols) == 0 {
		t.Fatal("expected at least one supported protocol")
	}
	modern := false
	for _, p := range res.Protocols {
		if p == "TLS 1.2" || p == "TLS 1.3" {
			modern = true
		}
	}
	if !modern {
		t.Errorf("expected TLS 1.2/1.3, got %v", res.Protocols)
	}

	// httptest's cert is self-signed.
	if !res.Cert.SelfSigned {
		t.Errorf("expected self-signed cert to be detected")
	}
	hasSelfSignedIssue := false
	for _, iss := range res.Issues {
		if strings.Contains(iss, "self-signed") {
			hasSelfSignedIssue = true
		}
	}
	if !hasSelfSignedIssue {
		t.Errorf("expected self-signed issue, got %v", res.Issues)
	}
	if res.NegotiatedCipher == "" {
		t.Errorf("expected a negotiated cipher")
	}
	if res.Cert.KeyType == "" {
		t.Errorf("expected a key type")
	}
}

func TestScanNonTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer srv.Close()

	addr := strings.TrimPrefix(srv.URL, "http://")
	if _, err := Scan(context.Background(), addr, Options{TimeoutMs: 1500}); err == nil {
		t.Fatal("expected error scanning a plaintext HTTP server")
	}
}

func TestNormalizeAddr(t *testing.T) {
	cases := map[string]string{
		"example.com":              "example.com:443",
		"https://example.com/path": "example.com:443",
		"example.com:8443":         "example.com:8443",
	}
	for in, want := range cases {
		if got := normalizeAddr(in); got != want {
			t.Errorf("normalizeAddr(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWeakSignature(t *testing.T) {
	if !isWeakSignature("SHA1-RSA") || !isWeakSignature("MD5-RSA") {
		t.Error("SHA1/MD5 signatures should be weak")
	}
	if isWeakSignature("SHA256-RSA") {
		t.Error("SHA256 should not be weak")
	}
}
