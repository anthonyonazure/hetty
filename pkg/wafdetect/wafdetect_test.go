package wafdetect

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDetectCloudflareHeaders(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "cloudflare")
		w.Header().Set("CF-RAY", "7a1b2c3d4e5f-EWR")
		fmt.Fprint(w, "hello")
	}))
	defer srv.Close()

	res, err := Detect(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !hasWAF(res, "Cloudflare") {
		t.Fatalf("expected Cloudflare, got %+v", res.Detected)
	}
}

func TestDetectSucuriBlocking(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("wafprobe") != "" {
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Denied - Sucuri Website Firewall")
			return
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	res, err := Detect(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if !hasWAF(res, "Sucuri CloudProxy") {
		t.Errorf("expected Sucuri, got %+v", res.Detected)
	}
	if !res.Blocked {
		t.Errorf("expected the malicious probe to be flagged as blocked (probe status %d, baseline %d)", res.ProbeStatus, res.BaselineStatus)
	}
}

func TestDetectClean(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		fmt.Fprint(w, "<html>normal site</html>")
	}))
	defer srv.Close()

	res, err := Detect(context.Background(), srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	if len(res.Detected) != 0 {
		t.Errorf("expected no WAF on a clean server, got %+v", res.Detected)
	}
	if res.Blocked {
		t.Errorf("clean server should not be flagged as blocking")
	}
}

func hasWAF(res Result, name string) bool {
	for _, d := range res.Detected {
		if d.Name == name {
			return true
		}
	}
	return false
}
