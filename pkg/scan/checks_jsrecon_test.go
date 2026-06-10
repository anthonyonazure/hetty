package scan

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func jsResponse(body string) (*RequestTemplate, *Response) {
	u, _ := url.Parse("https://ex.com/app.js")
	req := &RequestTemplate{Method: "GET", URL: u, Header: http.Header{}}
	res := &Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/javascript"}},
		Body:       []byte(body),
	}
	return req, res
}

func TestJSReconEndpoints(t *testing.T) {
	req, res := jsResponse(`
		const api = "/api/v2/internal/users";
		fetch("/admin/secret-panel");
		var u = "https://cdn.example.com/lib.js";
	`)
	findings := jsReconCheck{}.Check(req, res)

	var endpointFinding *Finding
	for i := range findings {
		if strings.Contains(findings[i].Name, "Endpoints discovered") {
			endpointFinding = &findings[i]
		}
	}
	if endpointFinding == nil {
		t.Fatal("expected an endpoints finding")
	}
	if !strings.Contains(endpointFinding.Evidence, "/api/v2/internal/users") {
		t.Errorf("missing endpoint; evidence:\n%s", endpointFinding.Evidence)
	}
	if !strings.Contains(endpointFinding.Evidence, "/admin/secret-panel") {
		t.Errorf("missing endpoint; evidence:\n%s", endpointFinding.Evidence)
	}
}

func TestJSReconIgnoresNonJS(t *testing.T) {
	u, _ := url.Parse("https://ex.com/page.html")
	req := &RequestTemplate{Method: "GET", URL: u, Header: http.Header{}}
	res := &Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/html"}}, Body: []byte(`"/api/x"`)}
	if f := (jsReconCheck{}).Check(req, res); f != nil {
		t.Errorf("HTML response should yield no JS recon findings, got %d", len(f))
	}
}

func TestSecretsCheckFindsLeak(t *testing.T) {
	u, _ := url.Parse("https://ex.com/app.js")
	req := &RequestTemplate{Method: "GET", URL: u, Header: http.Header{}}
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	res := &Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/javascript"}},
		Body:       []byte(`var aws = "` + awsKey + `";`),
	}
	findings := secretsCheck{}.Check(req, res)
	if len(findings) == 0 {
		t.Fatal("expected a leaked-secret finding")
	}
	f := findings[0]
	if f.Severity != SeverityCritical {
		t.Errorf("AWS key should be critical, got %s", f.Severity)
	}
	if strings.Contains(f.Evidence, awsKey) {
		t.Error("secret not redacted in finding evidence")
	}
}

func TestSecretsCheckSkipsBinary(t *testing.T) {
	u, _ := url.Parse("https://ex.com/img.png")
	req := &RequestTemplate{Method: "GET", URL: u, Header: http.Header{}}
	res := &Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"image/png"}}, Body: []byte("AKIA" + "IOSFODNN7EXAMPLE")}
	if f := (secretsCheck{}).Check(req, res); f != nil {
		t.Errorf("binary response should be skipped, got %d findings", len(f))
	}
}