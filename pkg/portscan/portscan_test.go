package portscan

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
)

func portOf(t *testing.T, rawURL string) int {
	t.Helper()
	_, portStr, err := net.SplitHostPort(hostPort(rawURL))
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	p, _ := strconv.Atoi(portStr)
	return p
}

func hostPort(rawURL string) string {
	s := rawURL
	if i := indexOf(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	return s
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func TestScanFindsOpenPortAndBanner(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	port := portOf(t, srv.URL)

	res, err := Scan(context.Background(), "127.0.0.1", Options{Ports: []int{port}, Banner: true, TimeoutMs: 1000})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Open) != 1 {
		t.Fatalf("expected 1 open port, got %d", len(res.Open))
	}
	if res.Open[0].Port != port || res.Open[0].State != "open" {
		t.Errorf("unexpected port result: %+v", res.Open[0])
	}
	// The httptest server isn't on a known port, so service is "unknown" but the
	// HTTP banner should still come back.
	if res.Open[0].Banner == "" {
		t.Errorf("expected an HTTP banner, got empty")
	}
}

func TestScanClosedPort(t *testing.T) {
	// Bind a listener then close it to get a port that is (almost certainly) closed.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()

	res, err := Scan(context.Background(), "127.0.0.1", Options{Ports: []int{port}, TimeoutMs: 500})
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if len(res.Open) != 0 {
		t.Fatalf("expected closed port, got %+v", res.Open)
	}
	if res.Scanned != 1 {
		t.Errorf("scanned = %d, want 1", res.Scanned)
	}
}

func TestServiceNameAndTopPorts(t *testing.T) {
	if ServiceName(443) != "https" || ServiceName(22) != "ssh" {
		t.Error("service name mapping wrong")
	}
	if ServiceName(65000) != "unknown" {
		t.Error("unknown port should map to 'unknown'")
	}
	if len(TopPorts(10)) != 10 || TopPorts(10)[0] != 80 {
		t.Error("TopPorts(10) wrong")
	}
	if len(TopPorts(1000)) != len(topPortsList) {
		t.Error("TopPorts should clamp to table size")
	}
}

func TestBareHost(t *testing.T) {
	cases := map[string]string{
		"https://example.com:8443/x": "example.com",
		"example.com:443":            "example.com",
		"10.0.0.1":                   "10.0.0.1",
		"http://10.0.0.1/a?b=c":      "10.0.0.1",
	}
	for in, want := range cases {
		if got := bareHost(in); got != want {
			t.Errorf("bareHost(%q) = %q, want %q", in, got, want)
		}
	}
}
