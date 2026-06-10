package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// jsReconCheck mines JavaScript responses for endpoints and leaked secrets. As
// the tester browses (or the spider crawls), every JS file passing through the
// proxy is automatically analyzed — surfacing hidden API routes and credentials
// that never appear in the rendered page. This is the LinkFinder/SecretFinder
// workflow built into the passive scanner.
type jsReconCheck struct{}

func (jsReconCheck) ID() string   { return "js-recon" }
func (jsReconCheck) Name() string { return "JavaScript recon" }

// endpointRe matches quoted strings that look like URL paths or absolute URLs.
var endpointRe = regexp.MustCompile(`["'` + "`" + `]((?:https?:)?/{1,2}[\w./?=&%~+:#@-]{2,}|/[\w./?=&%~+:#@-]{2,})["'` + "`" + `]`)

type secretPattern struct {
	name string
	re   *regexp.Regexp
}

// secretPatterns are high-signal credential formats. They favor precision over
// recall to keep noise down.
var secretPatterns = []secretPattern{
	{"AWS access key ID", regexp.MustCompile(`\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA)[A-Z0-9]{16}\b`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{10,48}\b`)},
	{"GitHub token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[0-9A-Za-z_]{20,}\b`)},
	{"Stripe secret key", regexp.MustCompile(`\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b`)},
	{"Generic API key assignment", regexp.MustCompile(`(?i)\b(?:api[_-]?key|secret|token|passwd|password|access[_-]?token)\b["'` + "`" + `]?\s*[:=]\s*["'` + "`" + `][0-9A-Za-z_\-./+]{12,}["'` + "`" + `]`)},
}

func isJS(req *RequestTemplate, res *Response) bool {
	if res != nil {
		ct := strings.ToLower(res.Header.Get("Content-Type"))
		if strings.Contains(ct, "javascript") || strings.Contains(ct, "ecmascript") {
			return true
		}
	}
	if req != nil && req.URL != nil {
		p := strings.ToLower(req.URL.Path)
		if strings.HasSuffix(p, ".js") || strings.HasSuffix(p, ".mjs") {
			return true
		}
	}
	return false
}

func (c jsReconCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil || len(res.Body) == 0 || !isJS(req, res) {
		return nil
	}

	body := string(res.Body)
	var findings []Finding

	// Secrets first — these are high severity.
	for _, sp := range secretPatterns {
		matches := sp.re.FindAllString(body, -1)
		if len(matches) == 0 {
			continue
		}
		uniq := dedupeStrings(matches, 5)
		findings = append(findings, Finding{
			Name:        "Secret in JavaScript: " + sp.name,
			Severity:    SeverityHigh,
			Confidence:  ConfidenceFirm,
			Evidence:    strings.Join(redactAll(uniq), "\n"),
			Description: fmt.Sprintf("A value matching the pattern of a %s was found in a JavaScript response. Leaked credentials in client-side code are accessible to anyone.", sp.name),
			Remediation: "Remove the secret from client-side code, rotate it, and move it server-side.",
			DedupKey:    "js-secret:" + sp.name,
			Request:     req,
			Response:    res,
		})
	}

	// Endpoints — informational recon.
	endpoints := extractEndpoints(body)
	if len(endpoints) > 0 {
		findings = append(findings, Finding{
			Name:        "Endpoints discovered in JavaScript",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceCertain,
			Evidence:    strings.Join(endpoints, "\n"),
			Description: fmt.Sprintf("%d candidate endpoint(s) were extracted from a JavaScript response. These may expose API routes not linked from the rendered application.", len(endpoints)),
			Remediation: "Review the discovered endpoints for unauthenticated or undocumented functionality.",
			DedupKey:    "js-endpoints",
			Request:     req,
			Response:    res,
		})
	}

	return findings
}

func extractEndpoints(body string) []string {
	matches := endpointRe.FindAllStringSubmatch(body, -1)
	seen := map[string]struct{}{}
	var out []string
	for _, m := range matches {
		ep := m[1]
		// Filter obvious noise: pure schemes, very short, or content types.
		if len(ep) < 3 || strings.HasPrefix(ep, "//") && !strings.Contains(ep[2:], "/") {
			continue
		}
		if _, ok := seen[ep]; ok {
			continue
		}
		seen[ep] = struct{}{}
		out = append(out, ep)
		if len(out) >= 200 {
			break
		}
	}
	sort.Strings(out)
	return out
}

func dedupeStrings(in []string, limit int) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
		if len(out) >= limit {
			break
		}
	}
	return out
}

// redactAll masks the middle of each secret so the report proves the match
// without fully re-exposing the credential.
func redactAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = redact(s)
	}
	return out
}

func redact(s string) string {
	if len(s) <= 12 {
		return s[:1] + strings.Repeat("*", len(s)-1)
	}
	keep := 4
	return s[:keep] + strings.Repeat("*", len(s)-2*keep) + s[len(s)-keep:]
}
