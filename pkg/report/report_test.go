package report

import (
	"strings"
	"testing"
	"time"

	"github.com/dstotijn/hetty/pkg/scan"
)

func sampleIssues() []scan.Issue {
	return []scan.Issue{
		{
			Name: "Reflected XSS", Severity: scan.SeverityHigh, Confidence: scan.ConfidenceFirm,
			URL: "https://ex.com/search", Method: "GET", Param: "q",
			Payload: "<script>alert(1)</script>", Evidence: "reflected unescaped",
			Description: "User input is reflected without encoding.", Remediation: "Encode output.",
		},
		{
			Name: "Missing security headers", Severity: scan.SeverityLow, Confidence: scan.ConfidenceCertain,
			URL: "https://ex.com/", Method: "GET",
		},
		{
			Name: "SQL injection", Severity: scan.SeverityCritical, Confidence: scan.ConfidenceCertain,
			URL: "https://ex.com/item", Method: "GET", Param: "id",
		},
	}
}

var fixedTime = time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC)

func TestMarkdownGroupsAndOrders(t *testing.T) {
	md := Markdown("Test Report", sampleIssues(), fixedTime)

	if !strings.Contains(md, "# Test Report") {
		t.Error("missing title")
	}
	if !strings.Contains(md, "3 finding(s)") {
		t.Error("missing finding count")
	}
	// Critical must appear before High, which appears before Low.
	ci := strings.Index(md, "SQL injection")
	hi := strings.Index(md, "Reflected XSS")
	li := strings.Index(md, "Missing security headers")
	if !(ci < hi && hi < li) {
		t.Errorf("issues not ordered by severity: critical=%d high=%d low=%d", ci, hi, li)
	}
	if !strings.Contains(md, "alert(1)") {
		t.Error("payload missing from markdown")
	}
}

func TestHTMLEscapesAndStandalone(t *testing.T) {
	htmlOut := HTML("Report", sampleIssues(), fixedTime)

	if !strings.HasPrefix(htmlOut, "<!DOCTYPE html>") {
		t.Error("not a standalone HTML document")
	}
	if !strings.Contains(htmlOut, "<style>") {
		t.Error("HTML should inline its CSS")
	}
	// The XSS payload must be escaped, not live in the report.
	if strings.Contains(htmlOut, "<script>alert(1)</script>") {
		t.Error("payload was not HTML-escaped — report is itself XSS-vulnerable")
	}
	if !strings.Contains(htmlOut, "&lt;script&gt;") {
		t.Error("expected escaped payload")
	}
}

func TestEmptyReport(t *testing.T) {
	md := Markdown("Empty", nil, fixedTime)
	if !strings.Contains(md, "0 finding(s)") {
		t.Error("empty report should still render with 0 findings")
	}
}
