package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dstotijn/hetty/pkg/scan"
)

// Triage is the AI's assessment of a scanner finding.
type Triage struct {
	IsLikelyReal      bool   `json:"isLikelyReal"`
	Confidence        string `json:"confidence"`        // low | medium | high
	FalsePositiveRisk string `json:"falsePositiveRisk"` // low | medium | high
	SuggestedSeverity string `json:"suggestedSeverity"`
	Rationale         string `json:"rationale"`
}

const triageSystem = `You are a senior application security analyst triaging automated vulnerability scanner findings.
Assess whether each finding is a true positive or a false positive, given the evidence. Be skeptical: scanners over-report.
Respond with ONLY a JSON object, no prose, no markdown, matching exactly:
{"isLikelyReal": bool, "confidence": "low"|"medium"|"high", "falsePositiveRisk": "low"|"medium"|"high", "suggestedSeverity": "info"|"low"|"medium"|"high"|"critical", "rationale": "one or two sentences"}`

// TriageIssue scores the false-positive risk of a single finding.
func (c *Client) TriageIssue(ctx context.Context, issue scan.Issue) (Triage, error) {
	if !c.Enabled() {
		return Triage{}, ErrDisabled
	}

	prompt := fmt.Sprintf(`Finding:
- Name: %s
- Severity (scanner): %s
- Confidence (scanner): %s
- URL: %s %s
- Parameter: %s
- Payload: %s
- Evidence: %s
- Description: %s`,
		issue.Name, issue.Severity, issue.Confidence, issue.Method, issue.URL,
		issue.Param, issue.Payload, truncate(issue.Evidence, 1500), truncate(issue.Description, 800))

	out, err := c.complete(ctx, triageSystem, prompt, 1024, true)
	if err != nil {
		return Triage{}, err
	}

	var t Triage
	if err := json.Unmarshal([]byte(extractJSON(out)), &t); err != nil {
		return Triage{}, fmt.Errorf("ai: could not parse triage response: %w", err)
	}
	return t, nil
}

// PayloadSuggestion is a set of AI-suggested payloads for a target.
type PayloadSuggestion struct {
	Payloads []string `json:"payloads"`
	Notes    string   `json:"notes"`
}

const payloadSystem = `You are a penetration-testing assistant. Given a vulnerability class and a target parameter, propose a short list of effective, varied test payloads (including encoding/WAF-evasion variants where relevant). These are for AUTHORIZED security testing only.
Respond with ONLY a JSON object, no prose, no markdown, matching exactly:
{"payloads": ["...", "..."], "notes": "one sentence on how to use them"}`

// SuggestPayloads proposes payloads for a vulnerability class and target.
func (c *Client) SuggestPayloads(ctx context.Context, vulnClass, url, param, extra string) (PayloadSuggestion, error) {
	if !c.Enabled() {
		return PayloadSuggestion{}, ErrDisabled
	}

	prompt := fmt.Sprintf(`Vulnerability class: %s
Target URL: %s
Parameter: %s
Additional context: %s

Propose up to 12 payloads.`, vulnClass, url, param, extra)

	out, err := c.complete(ctx, payloadSystem, prompt, 1024, false)
	if err != nil {
		return PayloadSuggestion{}, err
	}

	var ps PayloadSuggestion
	if err := json.Unmarshal([]byte(extractJSON(out)), &ps); err != nil {
		return PayloadSuggestion{}, fmt.Errorf("ai: could not parse payloads response: %w", err)
	}
	return ps, nil
}

const reportSystem = `You are a penetration tester writing a professional vulnerability assessment report in Markdown.
Given a list of confirmed findings, write a concise report: an executive summary, then one section per finding with impact, reproduction steps (proof of concept), and remediation. Group by severity, most critical first. Do not invent findings beyond those provided.`

// GenerateReport drafts a Markdown proof-of-concept report from the findings.
func (c *Client) GenerateReport(ctx context.Context, issues []scan.Issue) (string, error) {
	if !c.Enabled() {
		return "", ErrDisabled
	}
	if len(issues) == 0 {
		return "", fmt.Errorf("ai: no findings to report")
	}

	var b strings.Builder
	b.WriteString("Findings:\n")
	for i, is := range issues {
		fmt.Fprintf(&b, "%d. [%s] %s — %s %s", i+1, is.Severity, is.Name, is.Method, is.URL)
		if is.Param != "" {
			fmt.Fprintf(&b, " (param: %s)", is.Param)
		}
		b.WriteString("\n")
		if is.Evidence != "" {
			fmt.Fprintf(&b, "   evidence: %s\n", truncate(is.Evidence, 600))
		}
		if is.Payload != "" {
			fmt.Fprintf(&b, "   payload: %s\n", truncate(is.Payload, 300))
		}
	}

	return c.complete(ctx, reportSystem, b.String(), 8000, true)
}
