package scan

import (
	"fmt"
	"strings"

	"github.com/dstotijn/hetty/pkg/secrets"
)

// secretsCheck scans every text response for leaked credentials using the
// pkg/secrets pattern database. As the tester browses or the scanner crawls,
// any response containing an API key, token or private key is flagged with a
// redacted sample and a hint on how to validate the credential.
type secretsCheck struct{}

func (secretsCheck) ID() string   { return "leaked-secret" }
func (secretsCheck) Name() string { return "Leaked secret" }

func isTextResponse(res *Response) bool {
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	if ct == "" {
		return true
	}
	for _, t := range []string{"text", "json", "javascript", "ecmascript", "xml", "html", "csv", "yaml"} {
		if strings.Contains(ct, t) {
			return true
		}
	}
	return false
}

func (c secretsCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil || len(res.Body) == 0 || !isTextResponse(res) {
		return nil
	}

	matches := secrets.Scan(res.Body)
	if len(matches) == 0 {
		return nil
	}

	byName := map[string][]secrets.Match{}
	var order []string
	for _, m := range matches {
		if _, ok := byName[m.Pattern.Name]; !ok {
			order = append(order, m.Pattern.Name)
		}
		byName[m.Pattern.Name] = append(byName[m.Pattern.Name], m)
	}

	var findings []Finding
	for _, name := range order {
		ms := byName[name]
		redacted := make([]string, 0, len(ms))
		for _, m := range ms {
			redacted = append(redacted, m.Redacted)
		}
		sev := SeverityHigh
		if ms[0].Pattern.Severity == "critical" {
			sev = SeverityCritical
		}
		findings = append(findings, Finding{
			Name:        "Leaked secret: " + name,
			Severity:    sev,
			Confidence:  ConfidenceFirm,
			Evidence:    strings.Join(redacted, "\n"),
			Description: fmt.Sprintf("A value matching the %s pattern was found in a response. Leaked credentials are accessible to anyone who can read this response.", name),
			Remediation: "Rotate the credential and remove it from the response/client-side code. Validate: " + ms[0].Pattern.Validation,
			DedupKey:    "secret:" + name,
			Request:     req,
			Response:    res,
		})
	}
	return findings
}