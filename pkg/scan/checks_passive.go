package scan

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// BuiltinPassiveChecks returns the default set of passive checks.
func BuiltinPassiveChecks() []PassiveCheck {
	return []PassiveCheck{
		securityHeadersCheck{},
		serverBannerCheck{},
		cookieFlagsCheck{},
		infoDisclosureCheck{},
		directoryListingCheck{},
		jsReconCheck{},
		secretsCheck{},
		corsMisconfigCheck{},
		mixedContentFormCheck{},
		cacheableSensitiveCheck{},
		graphqlIntrospectionCheck{},
	}
}

func isTLS(req *RequestTemplate) bool {
	return req != nil && req.URL != nil && strings.EqualFold(req.URL.Scheme, "https")
}

// --- Missing security headers ----------------------------------------------

type securityHeadersCheck struct{}

func (securityHeadersCheck) ID() string   { return "missing-security-headers" }
func (securityHeadersCheck) Name() string { return "Missing security headers" }

func (c securityHeadersCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil || !isHTMLResponse(res) {
		return nil
	}

	var missing []string

	if res.Header.Get("Content-Security-Policy") == "" {
		missing = append(missing, "Content-Security-Policy")
	}
	if res.Header.Get("X-Content-Type-Options") == "" {
		missing = append(missing, "X-Content-Type-Options")
	}
	if res.Header.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(res.Header.Get("Content-Security-Policy")), "frame-ancestors") {
		missing = append(missing, "X-Frame-Options")
	}
	if res.Header.Get("Referrer-Policy") == "" {
		missing = append(missing, "Referrer-Policy")
	}
	if isTLS(req) && res.Header.Get("Strict-Transport-Security") == "" {
		missing = append(missing, "Strict-Transport-Security")
	}

	if len(missing) == 0 {
		return nil
	}

	return []Finding{{
		Name:        c.Name(),
		Severity:    SeverityLow,
		Confidence:  ConfidenceCertain,
		Evidence:    "Missing: " + strings.Join(missing, ", "),
		Description: "The HTML response is missing recommended security response headers, weakening defense-in-depth against clickjacking, MIME sniffing, and protocol downgrade.",
		Remediation: "Add the missing headers (CSP, X-Content-Type-Options: nosniff, X-Frame-Options/CSP frame-ancestors, Referrer-Policy, HSTS).",
		Response:    res,
		Request:     req,
	}}
}

// --- Server / technology banner disclosure ---------------------------------

type serverBannerCheck struct{}

func (serverBannerCheck) ID() string   { return "server-banner" }
func (serverBannerCheck) Name() string { return "Technology banner disclosure" }

func (c serverBannerCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil {
		return nil
	}

	var disclosed []string
	for _, h := range []string{"Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator"} {
		if v := res.Header.Get(h); v != "" {
			disclosed = append(disclosed, fmt.Sprintf("%s: %s", h, v))
		}
	}

	if len(disclosed) == 0 {
		return nil
	}

	return []Finding{{
		Name:        c.Name(),
		Severity:    SeverityInfo,
		Confidence:  ConfidenceCertain,
		Evidence:    strings.Join(disclosed, "; "),
		Description: "Response headers disclose server software and versions, helping an attacker fingerprint known vulnerabilities.",
		Remediation: "Suppress or genericize Server/X-Powered-By and framework version headers.",
		DedupKey:    strings.Join(disclosed, "|"),
		Response:    res,
		Request:     req,
	}}
}

// --- Insecure cookies ------------------------------------------------------

type cookieFlagsCheck struct{}

func (cookieFlagsCheck) ID() string   { return "insecure-cookie" }
func (cookieFlagsCheck) Name() string { return "Insecure cookie attributes" }

func (c cookieFlagsCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil {
		return nil
	}

	resp := &http.Response{Header: res.Header}
	cookies := resp.Cookies()
	if len(cookies) == 0 {
		return nil
	}

	var findings []Finding

	for _, ck := range cookies {
		var problems []string
		if !ck.HttpOnly {
			problems = append(problems, "missing HttpOnly")
		}
		if isTLS(req) && !ck.Secure {
			problems = append(problems, "missing Secure")
		}
		if ck.SameSite == http.SameSiteDefaultMode || ck.SameSite == http.SameSiteNoneMode {
			problems = append(problems, "weak/absent SameSite")
		}

		if len(problems) == 0 {
			continue
		}

		findings = append(findings, Finding{
			Name:        c.Name(),
			Severity:    SeverityLow,
			Confidence:  ConfidenceFirm,
			Evidence:    fmt.Sprintf("Set-Cookie %q: %s", ck.Name, strings.Join(problems, ", ")),
			Description: "A response cookie is set without recommended protective attributes, increasing the risk of theft via XSS or transport, and CSRF.",
			Remediation: "Set HttpOnly and Secure on session cookies, and an explicit SameSite=Lax/Strict.",
			DedupKey:    "cookie:" + ck.Name,
			Response:    res,
			Request:     req,
		})
	}

	return findings
}

// --- Information / error disclosure ----------------------------------------

var infoDisclosureSignatures = []struct {
	re   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`Traceback \(most recent call last\):`), "Python traceback"},
	{regexp.MustCompile(`(?i)Exception in thread "`), "Java stack trace"},
	{regexp.MustCompile(`(?i)\bat [\w.$]+\([\w.]+\.java:\d+\)`), "Java stack trace"},
	{regexp.MustCompile(`(?i)<b>(Fatal error|Warning|Notice|Parse error)</b>:`), "PHP error"},
	{regexp.MustCompile(`(?i)on line \d+ in (/|[A-Za-z]:\\)`), "PHP error with path"},
	{regexp.MustCompile(`(?i)System\.[\w.]+Exception`), ".NET exception"},
	{regexp.MustCompile(`(?i)Microsoft OLE DB Provider`), "ASP/ADO error"},
	{regexp.MustCompile(`(?i)Stack trace:`), "Stack trace"},
}

type infoDisclosureCheck struct{}

func (infoDisclosureCheck) ID() string   { return "info-disclosure" }
func (infoDisclosureCheck) Name() string { return "Verbose error / stack trace disclosure" }

func (c infoDisclosureCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil || len(res.Body) == 0 {
		return nil
	}

	body := string(res.Body)

	for _, sig := range infoDisclosureSignatures {
		if loc := sig.re.FindString(body); loc != "" {
			return []Finding{{
				Name:        c.Name(),
				Severity:    SeverityMedium,
				Confidence:  ConfidenceFirm,
				Evidence:    snippet(body, loc, 160),
				Description: fmt.Sprintf("The response leaks a %s, exposing internal implementation details and file paths useful to an attacker.", sig.what),
				Remediation: "Disable debug output in production and return generic error pages; log details server-side only.",
				DedupKey:    sig.what,
				Response:    res,
				Request:     req,
			}}
		}
	}

	return nil
}

// --- Directory listing -----------------------------------------------------

var dirListingRe = regexp.MustCompile(`(?i)<title>Index of /|<h1>Index of /|Directory listing for /`)

type directoryListingCheck struct{}

func (directoryListingCheck) ID() string   { return "directory-listing" }
func (directoryListingCheck) Name() string { return "Directory listing enabled" }

func (c directoryListingCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil || len(res.Body) == 0 {
		return nil
	}

	if dirListingRe.MatchString(string(res.Body)) {
		return []Finding{{
			Name:        c.Name(),
			Severity:    SeverityLow,
			Confidence:  ConfidenceFirm,
			Evidence:    dirListingRe.FindString(string(res.Body)),
			Description: "The server returned an automatic directory index, exposing file names that may include backups, source, or sensitive data.",
			Remediation: "Disable automatic directory indexing (e.g. Apache 'Options -Indexes').",
			Response:    res,
			Request:     req,
		}}
	}

	return nil
}
