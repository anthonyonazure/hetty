package ai

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dstotijn/hetty/pkg/scan"
)

// mockAPI returns a server that asserts the request shape and replies with the
// given assistant text wrapped in the Messages API response envelope.
func mockAPI(t *testing.T, replyText string, capture *messageRequest) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") == "" {
			t.Error("missing x-api-key header")
		}
		if r.Header.Get("anthropic-version") != anthropicVer {
			t.Errorf("anthropic-version = %q", r.Header.Get("anthropic-version"))
		}
		body, _ := io.ReadAll(r.Body)
		if capture != nil {
			_ = json.Unmarshal(body, capture)
		}
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"content":     []map[string]string{{"type": "text", "text": replyText}},
			"stop_reason": "end_turn",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
}

func TestDisabledClient(t *testing.T) {
	c := NewClient(Config{})
	if c.Enabled() {
		t.Error("client without key should be disabled")
	}
	if _, err := c.TriageIssue(context.Background(), scan.Issue{}); err != ErrDisabled {
		t.Errorf("expected ErrDisabled, got %v", err)
	}
}

func TestTriageParsesJSON(t *testing.T) {
	var captured messageRequest
	srv := mockAPI(t, `{"isLikelyReal": true, "confidence": "high", "falsePositiveRisk": "low", "suggestedSeverity": "high", "rationale": "Payload reflected unescaped."}`, &captured)
	defer srv.Close()

	c := NewClient(Config{APIKey: "test-key", BaseURL: srv.URL})
	tr, err := c.TriageIssue(context.Background(), scan.Issue{
		Name: "Reflected XSS", Severity: scan.SeverityHigh, URL: "https://ex.com/s", Method: "GET", Param: "q",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !tr.IsLikelyReal || tr.Confidence != "high" || tr.SuggestedSeverity != "high" {
		t.Errorf("triage parsed wrong: %+v", tr)
	}
	if captured.Model != DefaultModel {
		t.Errorf("model = %q, want default %q", captured.Model, DefaultModel)
	}
	if captured.Thinking == nil || captured.Thinking.Type != "adaptive" {
		t.Error("triage should use adaptive thinking")
	}
}

func TestTriageToleratesFences(t *testing.T) {
	srv := mockAPI(t, "Here is my assessment:\n```json\n{\"isLikelyReal\": false, \"confidence\": \"medium\", \"falsePositiveRisk\": \"high\", \"suggestedSeverity\": \"info\", \"rationale\": \"Generic banner.\"}\n```", nil)
	defer srv.Close()

	c := NewClient(Config{APIKey: "k", BaseURL: srv.URL})
	tr, err := c.TriageIssue(context.Background(), scan.Issue{Name: "Server banner"})
	if err != nil {
		t.Fatal(err)
	}
	if tr.IsLikelyReal || tr.FalsePositiveRisk != "high" {
		t.Errorf("triage with fences parsed wrong: %+v", tr)
	}
}

func TestSuggestPayloads(t *testing.T) {
	var captured messageRequest
	srv := mockAPI(t, `{"payloads": ["<script>alert(1)</script>", "'\"><svg onload=alert(1)>"], "notes": "Try in the q parameter."}`, &captured)
	defer srv.Close()

	c := NewClient(Config{APIKey: "k", BaseURL: srv.URL})
	ps, err := c.SuggestPayloads(context.Background(), "xss", "https://ex.com/s", "q", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(ps.Payloads) != 2 {
		t.Errorf("payloads = %v", ps.Payloads)
	}
	if captured.Thinking != nil {
		t.Error("payload suggestion should not use thinking (latency)")
	}
}

func TestGenerateReport(t *testing.T) {
	srv := mockAPI(t, "# Security Assessment\n\n## Reflected XSS (High)\n...", nil)
	defer srv.Close()

	c := NewClient(Config{APIKey: "k", BaseURL: srv.URL})
	md, err := c.GenerateReport(context.Background(), []scan.Issue{{Name: "Reflected XSS", Severity: scan.SeverityHigh, URL: "https://ex.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md, "Security Assessment") {
		t.Errorf("report = %q", md)
	}
}

func TestAPIErrorSurfaced(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`))
	}))
	defer srv.Close()

	c := NewClient(Config{APIKey: "bad", BaseURL: srv.URL})
	_, err := c.TriageIssue(context.Background(), scan.Issue{Name: "x"})
	if err == nil || !strings.Contains(err.Error(), "authentication_error") {
		t.Errorf("expected surfaced API error, got %v", err)
	}
}
