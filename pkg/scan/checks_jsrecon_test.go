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

func TestJSReconSecrets(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	googleKey := "AIza" + "SyB1234567890abcdefghijklmnopqrstuv"
	req, res := jsResponse(`var key = "` + googleKey + `"; const aws="` + awsKey + `";`)
	findings := jsReconCheck{}.Check(req, res)

	names := map[string]bool{}
	for _, f := range findings {
		names[f.Name] = true
		if strings.Contains(f.Name, "Secret") && f.Severity != SeverityHigh {
			t.Errorf("secret finding %q should be high severity", f.Name)
		}
	}
	if !names["Secret in JavaScript: Google API key"] {
		t.Errorf("missing Google API key finding; got %v", names)
	}
	if !names["Secret in JavaScript: AWS access key ID"] {
		t.Errorf("missing AWS key finding; got %v", names)
	}
}

func TestJSReconRedacts(t *testing.T) {
	awsKey := "AKIA" + "IOSFODNN7EXAMPLE"
	req, res := jsResponse(`const aws="` + awsKey + `";`)
	findings := jsReconCheck{}.Check(req, res)
	for _, f := range findings {
		if strings.Contains(f.Name, "Secret") {
			if strings.Contains(f.Evidence, awsKey) {
				t.Error("secret was not redacted in evidence")
			}
			if !strings.Contains(f.Evidence, "*") {
				t.Error("expected redaction asterisks")
			}
		}
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