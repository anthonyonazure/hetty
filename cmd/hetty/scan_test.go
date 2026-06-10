package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/dstotijn/hetty/pkg/scan"
)

func TestHeadlessScanFindsXSS(t *testing.T) {
	target := vulnTarget()
	defer target.Close()

	old := scan.CmdInjectionDelaySeconds
	scan.CmdInjectionDelaySeconds = 2
	defer func() { scan.CmdInjectionDelaySeconds = old }()

	issues, err := runScan(context.Background(), scanParams{
		target:  target.URL + "/reflect?q=hi",
		timeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, is := range issues {
		if is.CheckID == "xss-reflected" {
			found = true
		}
	}
	if !found {
		t.Errorf("headless scan did not find reflected XSS; issues = %d", len(issues))
	}
}

func TestHeadlessScanCrawl(t *testing.T) {
	target := linkedTarget()
	defer target.Close()

	old := scan.CmdInjectionDelaySeconds
	scan.CmdInjectionDelaySeconds = 2
	defer func() { scan.CmdInjectionDelaySeconds = old }()

	// Crawl mode should scan more than one URL without error.
	_, err := runScan(context.Background(), scanParams{
		target:   target.URL + "/",
		crawl:    true,
		depth:    1,
		maxPages: 10,
		timeout:  10 * time.Second,
	})
	if err != nil {
		t.Fatalf("headless crawl-scan failed: %v", err)
	}
}

func TestRenderReportFormats(t *testing.T) {
	issues := []scan.Issue{
		{Name: "Reflected XSS", Severity: scan.SeverityHigh, URL: "https://ex.com/s", Method: "GET", Param: "q"},
	}

	md, err := renderReport("md", issues)
	if err != nil || !strings.Contains(md, "Reflected XSS") {
		t.Errorf("markdown report wrong: %v / %q", err, md)
	}

	htmlOut, err := renderReport("html", issues)
	if err != nil || !strings.HasPrefix(htmlOut, "<!DOCTYPE html>") {
		t.Errorf("html report wrong: %v", err)
	}

	jsonOut, err := renderReport("json", issues)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Issues []scan.Issue `json:"issues"`
	}
	if err := json.Unmarshal([]byte(jsonOut), &parsed); err != nil {
		t.Fatalf("json report not valid JSON: %v", err)
	}
	if len(parsed.Issues) != 1 {
		t.Errorf("json report issue count = %d, want 1", len(parsed.Issues))
	}

	if _, err := renderReport("bogus", issues); err == nil {
		t.Error("expected error for invalid format")
	}
}

func TestSeverityRankCLI(t *testing.T) {
	if severityRankCLI(scan.SeverityCritical) >= severityRankCLI(scan.SeverityHigh) {
		t.Error("critical should outrank high")
	}
	if severityThresholds["high"] != 1 {
		t.Error("high threshold should be 1")
	}
}
