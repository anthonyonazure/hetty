package scan

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// jsReconCheck mines JavaScript responses for endpoints (the LinkFinder
// workflow). Secret detection across all responses is handled separately by
// secretsCheck.
type jsReconCheck struct{}

func (jsReconCheck) ID() string   { return "js-recon" }
func (jsReconCheck) Name() string { return "JavaScript recon" }

// endpointRe matches quoted strings that look like URL paths or absolute URLs.
var endpointRe = regexp.MustCompile(`["'` + "`" + `]((?:https?:)?/{1,2}[\w./?=&%~+:#@-]{2,}|/[\w./?=&%~+:#@-]{2,})["'` + "`" + `]`)

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

	endpoints := extractEndpoints(string(res.Body))
	if len(endpoints) == 0 {
		return nil
	}

	return []Finding{{
		Name:        "Endpoints discovered in JavaScript",
		Severity:    SeverityInfo,
		Confidence:  ConfidenceCertain,
		Evidence:    strings.Join(endpoints, "\n"),
		Description: fmt.Sprintf("%d candidate endpoint(s) were extracted from a JavaScript response. These may expose API routes not linked from the rendered application.", len(endpoints)),
		Remediation: "Review the discovered endpoints for unauthenticated or undocumented functionality.",
		DedupKey:    "js-endpoints",
		Request:     req,
		Response:    res,
	}}
}

func extractEndpoints(body string) []string {
	matches := endpointRe.FindAllStringSubmatch(body, -1)
	seen := map[string]struct{}{}
	var out []string
	for _, m := range matches {
		ep := m[1]
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
