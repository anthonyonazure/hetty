package rules_test

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dstotijn/hetty/pkg/rules"
)

func TestRequestHeaderReplace(t *testing.T) {
	e := rules.NewEngine()
	if err := e.SetRules([]rules.Rule{{
		ID: "ua", Enabled: true, Part: rules.PartRequestHeader,
		Match: "User-Agent: .*", Replace: "User-Agent: HettyScanner", IsRegex: true,
	}}); err != nil {
		t.Fatalf("set rules: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "https://example.com/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")

	e.RequestModifier(func(_ *http.Request) {})(req)

	if got := req.Header.Get("User-Agent"); got != "HettyScanner" {
		t.Errorf("User-Agent = %q, want HettyScanner", got)
	}
}

func TestRequestBodyReplace(t *testing.T) {
	e := rules.NewEngine()
	if err := e.SetRules([]rules.Rule{{
		ID: "b", Enabled: true, Part: rules.PartRequestBody,
		Match: "level=user", Replace: "level=admin",
	}}); err != nil {
		t.Fatalf("set rules: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("level=user&x=1"))

	e.RequestModifier(func(_ *http.Request) {})(req)

	body, _ := io.ReadAll(req.Body)
	if !strings.Contains(string(body), "level=admin") {
		t.Errorf("body = %q, want level=admin", body)
	}
	if req.ContentLength != int64(len(body)) {
		t.Errorf("ContentLength = %d, want %d", req.ContentLength, len(body))
	}
}

func TestResponseBodyReplace(t *testing.T) {
	e := rules.NewEngine()
	if err := e.SetRules([]rules.Rule{{
		ID: "csp", Enabled: true, Part: rules.PartResponseBody,
		Match: "http://", Replace: "https://",
	}}); err != nil {
		t.Fatalf("set rules: %v", err)
	}

	res := &http.Response{
		StatusCode: 200,
		Header:     http.Header{},
		Body:       io.NopCloser(strings.NewReader("link: http://insecure.example")),
	}

	if err := e.ResponseModifier(func(_ *http.Response) error { return nil })(res); err != nil {
		t.Fatalf("modifier: %v", err)
	}

	body, _ := io.ReadAll(res.Body)
	if !strings.Contains(string(body), "https://insecure.example") {
		t.Errorf("body = %q, want https://", body)
	}
}

func TestDisabledRuleIgnored(t *testing.T) {
	e := rules.NewEngine()
	_ = e.SetRules([]rules.Rule{{
		ID: "x", Enabled: false, Part: rules.PartRequestBody,
		Match: "a", Replace: "b",
	}})

	req := httptest.NewRequest(http.MethodPost, "https://example.com/", strings.NewReader("aaa"))
	e.RequestModifier(func(_ *http.Request) {})(req)

	body, _ := io.ReadAll(req.Body)
	if string(body) != "aaa" {
		t.Errorf("disabled rule applied: body = %q", body)
	}
}

func TestInvalidRegexRejected(t *testing.T) {
	e := rules.NewEngine()
	err := e.SetRules([]rules.Rule{{
		ID: "bad", Enabled: true, Part: rules.PartRequestBody,
		Match: "(", IsRegex: true,
	}})
	if err == nil {
		t.Error("expected error for invalid regex")
	}
}
