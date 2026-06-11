package scan

import (
	"net/http"
	"net/url"
	"testing"
)

func mkReq(t *testing.T, method, rawURL string, hdr http.Header) *RequestTemplate {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	if hdr == nil {
		hdr = http.Header{}
	}
	return &RequestTemplate{Method: method, URL: u, Proto: "HTTP/1.1", Header: hdr}
}

func TestCORSReflectedOriginWithCredentials(t *testing.T) {
	req := mkReq(t, "GET", "https://api.example.com/data", http.Header{"Origin": {"https://evil.example"}})
	res := &Response{StatusCode: 200, Header: http.Header{
		"Access-Control-Allow-Origin":      {"https://evil.example"},
		"Access-Control-Allow-Credentials": {"true"},
	}}

	f := corsMisconfigCheck{}.Check(req, res)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != SeverityHigh {
		t.Errorf("reflected origin + credentials should be High, got %s", f[0].Severity)
	}
}

func TestCORSNullOrigin(t *testing.T) {
	req := mkReq(t, "GET", "https://api.example.com/data", nil)
	res := &Response{StatusCode: 200, Header: http.Header{"Access-Control-Allow-Origin": {"null"}}}
	if len(corsMisconfigCheck{}.Check(req, res)) != 1 {
		t.Fatal("expected finding for ACAO: null")
	}
}

func TestCORSSameOriginIsClean(t *testing.T) {
	req := mkReq(t, "GET", "https://api.example.com/data", http.Header{"Origin": {"https://api.example.com"}})
	res := &Response{StatusCode: 200, Header: http.Header{"Access-Control-Allow-Origin": {"https://api.example.com"}}}
	if f := (corsMisconfigCheck{}.Check(req, res)); len(f) != 0 {
		t.Fatalf("same-origin reflection should not fire, got %v", f)
	}
}

func TestMixedContentForm(t *testing.T) {
	req := mkReq(t, "GET", "https://shop.example/login", nil)
	res := &Response{StatusCode: 200,
		Header: http.Header{"Content-Type": {"text/html"}},
		Body:   []byte(`<html><form action="http://shop.example/auth"><input type="password" name="p"></form></html>`),
	}
	f := mixedContentFormCheck{}.Check(req, res)
	if len(f) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(f))
	}
	if f[0].Severity != SeverityMedium {
		t.Errorf("password form over http should be Medium, got %s", f[0].Severity)
	}
}

func TestMixedContentFormHTTPSeedIgnored(t *testing.T) {
	req := mkReq(t, "GET", "http://shop.example/login", nil) // not TLS
	res := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: []byte(`<form action="http://shop.example/auth"></form>`)}
	if len(mixedContentFormCheck{}.Check(req, res)) != 0 {
		t.Fatal("mixed-content should only apply to HTTPS pages")
	}
}

func TestCacheableAuthenticatedResponse(t *testing.T) {
	req := mkReq(t, "GET", "https://app.example/me", http.Header{"Cookie": {"session=abc"}})
	res := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}},
		Body: []byte("<html>profile</html>")}
	if len(cacheableSensitiveCheck{}.Check(req, res)) != 1 {
		t.Fatal("expected cacheable-authenticated finding")
	}

	res.Header.Set("Cache-Control", "no-store")
	if len(cacheableSensitiveCheck{}.Check(req, res)) != 0 {
		t.Fatal("no-store should suppress the finding")
	}
}

func TestCacheableRequiresCredentials(t *testing.T) {
	req := mkReq(t, "GET", "https://app.example/public", nil)
	res := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/html"}}, Body: []byte("x")}
	if len(cacheableSensitiveCheck{}.Check(req, res)) != 0 {
		t.Fatal("unauthenticated request should not fire")
	}
}

func TestGraphQLIntrospection(t *testing.T) {
	req := mkReq(t, "POST", "https://api.example/graphql", nil)
	res := &Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: []byte(`{"data":{"__schema":{"types":[{"name":"Query"}]}}}`)}
	if len(graphqlIntrospectionCheck{}.Check(req, res)) != 1 {
		t.Fatal("expected graphql-introspection finding")
	}
}
