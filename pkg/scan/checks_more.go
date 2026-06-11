package scan

import (
	"fmt"
	"regexp"
	"strings"
)

// This file adds breadth to the built-in check library: CORS misconfiguration,
// mixed-content forms, cacheable authenticated responses, and GraphQL
// introspection (passive), plus host-header injection (active).

// --- CORS misconfiguration (passive) ---------------------------------------

type corsMisconfigCheck struct{}

func (corsMisconfigCheck) ID() string   { return "cors-misconfig" }
func (corsMisconfigCheck) Name() string { return "CORS misconfiguration" }

func (c corsMisconfigCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil {
		return nil
	}

	acao := res.Header.Get("Access-Control-Allow-Origin")
	if acao == "" {
		return nil
	}
	acac := strings.EqualFold(res.Header.Get("Access-Control-Allow-Credentials"), "true")

	var (
		evidence string
		sev      Severity
		conf     Confidence
	)

	switch {
	case acao == "*" && acac:
		// Browsers reject *+credentials, but it signals a broken policy.
		evidence = "Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true"
		sev, conf = SeverityMedium, ConfidenceFirm
	case strings.EqualFold(acao, "null"):
		evidence = "Access-Control-Allow-Origin: null (any sandboxed/opaque origin is trusted)"
		sev, conf = SeverityMedium, ConfidenceFirm
	case req != nil && acao != "*" && reflectsOrigin(req, acao):
		evidence = fmt.Sprintf("Access-Control-Allow-Origin reflects the request Origin (%s)", acao)
		if acac {
			sev, conf = SeverityHigh, ConfidenceFirm
		} else {
			sev, conf = SeverityMedium, ConfidenceFirm
		}
	default:
		return nil
	}

	return []Finding{{
		Name:        c.Name(),
		Severity:    sev,
		Confidence:  conf,
		Evidence:    evidence,
		Description: "The resource's CORS policy trusts origins it should not, potentially letting a malicious site read authenticated responses cross-origin.",
		Remediation: "Reflect only an explicit allow-list of trusted origins; never combine a wildcard or reflected origin with Access-Control-Allow-Credentials: true; avoid trusting the 'null' origin.",
		DedupKey:    "cors:" + acao,
		Response:    res,
		Request:     req,
	}}
}

func reflectsOrigin(req *RequestTemplate, acao string) bool {
	origin := req.Header.Get("Origin")
	if origin == "" || req.URL == nil {
		return false
	}
	// Only interesting if the reflected origin is cross-origin.
	if strings.EqualFold(origin, req.URL.Scheme+"://"+req.URL.Host) {
		return false
	}
	return strings.EqualFold(strings.TrimRight(acao, "/"), strings.TrimRight(origin, "/"))
}

// --- Mixed content / insecure form action (passive) ------------------------

var (
	formActionRe = regexp.MustCompile(`(?i)<form\b[^>]*\baction\s*=\s*["']?(http://[^"'\s>]+)`)
	passwordRe   = regexp.MustCompile(`(?i)<input\b[^>]*\btype\s*=\s*["']?password`)
)

type mixedContentFormCheck struct{}

func (mixedContentFormCheck) ID() string   { return "insecure-form-action" }
func (mixedContentFormCheck) Name() string { return "Form submits over cleartext HTTP" }

func (c mixedContentFormCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil || !isTLS(req) || !isHTMLResponse(res) || len(res.Body) == 0 {
		return nil
	}
	body := string(res.Body)

	if m := formActionRe.FindStringSubmatch(body); m != nil {
		sev := SeverityLow
		if passwordRe.MatchString(body) {
			sev = SeverityMedium
		}
		return []Finding{{
			Name:        c.Name(),
			Severity:    sev,
			Confidence:  ConfidenceFirm,
			Evidence:    "form action=" + m[1],
			Description: "An HTTPS page contains a form that submits to a cleartext http:// URL, exposing submitted data (potentially credentials) to network attackers.",
			Remediation: "Point form actions at https:// endpoints and serve all resources over TLS.",
			DedupKey:    "insecure-form:" + m[1],
			Response:    res,
			Request:     req,
		}}
	}
	return nil
}

// --- Cacheable authenticated response (passive) ----------------------------

type cacheableSensitiveCheck struct{}

func (cacheableSensitiveCheck) ID() string   { return "cacheable-authenticated-response" }
func (cacheableSensitiveCheck) Name() string { return "Cacheable response to authenticated request" }

func (c cacheableSensitiveCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if req == nil || res == nil {
		return nil
	}
	// Only meaningful when the request carried credentials.
	authd := req.Header.Get("Authorization") != "" ||
		req.Header.Get("Cookie") != "" ||
		req.Header.Get("X-Api-Key") != ""
	if !authd {
		return nil
	}

	cc := strings.ToLower(res.Header.Get("Cache-Control"))
	if strings.Contains(cc, "no-store") || strings.Contains(cc, "private") {
		return nil
	}
	// Heuristic: only flag content types worth caching/sniffing.
	if !isHTMLResponse(res) && !isTextResponse(res) {
		return nil
	}

	return []Finding{{
		Name:        c.Name(),
		Severity:    SeverityLow,
		Confidence:  ConfidenceTentative,
		Evidence:    fmt.Sprintf("Cache-Control: %q on an authenticated response", res.Header.Get("Cache-Control")),
		Description: "A response to a request bearing credentials is not marked no-store/private, so it may be stored by shared caches or the browser and disclosed to another user.",
		Remediation: "Set Cache-Control: no-store (or private) on authenticated, user-specific responses.",
		DedupKey:    "cacheable-auth",
		Response:    res,
		Request:     req,
	}}
}

// --- GraphQL introspection exposed (passive) -------------------------------

var graphqlIntrospectionRe = regexp.MustCompile(`"__schema"\s*:\s*\{`)

type graphqlIntrospectionCheck struct{}

func (graphqlIntrospectionCheck) ID() string   { return "graphql-introspection" }
func (graphqlIntrospectionCheck) Name() string { return "GraphQL introspection enabled" }

func (c graphqlIntrospectionCheck) Check(req *RequestTemplate, res *Response) []Finding {
	if res == nil || len(res.Body) == 0 {
		return nil
	}
	ct := strings.ToLower(res.Header.Get("Content-Type"))
	if !strings.Contains(ct, "json") {
		return nil
	}
	if graphqlIntrospectionRe.Match(res.Body) {
		return []Finding{{
			Name:        c.Name(),
			Severity:    SeverityLow,
			Confidence:  ConfidenceFirm,
			Evidence:    snippet(string(res.Body), `"__schema"`, 120),
			Description: "The GraphQL endpoint answered an introspection query, revealing the full schema (types, fields, mutations) and broadening the attack surface for an adversary.",
			Remediation: "Disable introspection in production or restrict it to authenticated/internal callers.",
			DedupKey:    "graphql-introspection",
			Response:    res,
			Request:     req,
		}}
	}
	return nil
}

// --- Host header injection (active) ----------------------------------------

var hostPoisonHeaders = []string{"X-Forwarded-Host", "X-Host", "X-Forwarded-Server", "X-Original-Host"}

type hostHeaderInjectionCheck struct{}

func (hostHeaderInjectionCheck) ID() string   { return "host-header-injection" }
func (hostHeaderInjectionCheck) Name() string { return "Host header injection (X-Forwarded-Host poisoning)" }

func (c hostHeaderInjectionCheck) Run(sc *ScanContext) []Finding {
	// Per-request check: run once, on the first insertion point only.
	if !sc.First {
		return nil
	}

	const marker = "hetty-hostpoison.example"

	rt := sc.Base.Clone()
	for _, h := range hostPoisonHeaders {
		rt.Header.Set(h, marker)
	}

	res, err := sc.SendRaw(rt)
	if err != nil || res == nil {
		return nil
	}

	// Avoid false positives if the marker somehow already appeared at baseline.
	if sc.Baseline != nil && strings.Contains(string(sc.Baseline.Body), marker) {
		return nil
	}

	loc := res.Header.Get("Location")
	body := string(res.Body)

	var where string
	switch {
	case strings.Contains(loc, marker):
		where = "Location redirect header"
	case strings.Contains(body, marker):
		where = "response body"
	default:
		return nil
	}

	return []Finding{{
		Name:        c.Name(),
		Severity:    SeverityMedium,
		Confidence:  ConfidenceFirm,
		Payload:     marker,
		Evidence:    fmt.Sprintf("Injected X-Forwarded-Host was reflected in the %s", where),
		Description: "The application trusts the client-supplied X-Forwarded-Host (or similar) header and reflects it into links/redirects, enabling password-reset poisoning, cache poisoning, and open redirection.",
		Remediation: "Build absolute URLs from a server-side configured canonical host, not from client-controlled Host/X-Forwarded-* headers; validate against an allow-list.",
		DedupKey:    "host-header-injection",
		Request:     rt,
		Response:    res,
	}}
}
