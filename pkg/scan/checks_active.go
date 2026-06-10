package scan

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// BuiltinActiveChecks returns the default set of active checks.
func BuiltinActiveChecks() []ActiveCheck {
	return []ActiveCheck{
		reflectedXSSCheck{},
		sqlInjectionCheck{},
		commandInjectionCheck{},
		pathTraversalCheck{},
		openRedirectCheck{},
		sstiCheck{},
		crlfInjectionCheck{},
		oobInjectionCheck{},
	}
}

// --- Reflected XSS ---------------------------------------------------------

type reflectedXSSCheck struct{}

func (reflectedXSSCheck) ID() string   { return "xss-reflected" }
func (reflectedXSSCheck) Name() string { return "Reflected Cross-Site Scripting (XSS)" }

func (c reflectedXSSCheck) Run(sc *ScanContext) []Finding {
	nonce := randToken(5)
	breakout := fmt.Sprintf(`%s"'><svg/onload=alert(1)>`, nonce)

	res, req, err := sc.Send(breakout)
	if err != nil || res == nil {
		return nil
	}

	body := string(res.Body)

	// Strongest signal: the breakout markup is reflected verbatim.
	if strings.Contains(body, breakout) {
		return []Finding{{
			Name:        c.Name(),
			Severity:    SeverityHigh,
			Confidence:  ConfidenceFirm,
			Payload:     breakout,
			Evidence:    snippet(body, nonce, 160),
			Description: "User input was reflected into the response without output encoding, allowing arbitrary HTML/JavaScript to execute in the victim's browser.",
			Remediation: "Context-aware output encode all user input rendered into HTML, and apply a restrictive Content-Security-Policy.",
			Request:     req,
			Response:    res,
		}}
	}

	// Weaker signal: the marker reflects but the special characters were
	// encoded. Report as informational, since the context may still be
	// exploitable.
	if strings.Contains(body, nonce) {
		return []Finding{{
			Name:        "Input reflected in response",
			Severity:    SeverityInfo,
			Confidence:  ConfidenceTentative,
			Payload:     breakout,
			Evidence:    snippet(body, nonce, 160),
			Description: "User input was reflected in the response. Special characters appear to be encoded, but the reflection context should be reviewed for XSS.",
			Remediation: "Ensure context-aware output encoding is applied for every reflection context (HTML, attribute, JS, URL).",
			DedupKey:    "reflected-input",
			Request:     req,
			Response:    res,
		}}
	}

	return nil
}

// --- SQL injection (error-based) ------------------------------------------

var sqlErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*\bmysqli?_`),
	regexp.MustCompile(`(?i)valid MySQL result`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)pg_query\(\):`),
	regexp.MustCompile(`(?i)unterminated quoted string`),
	regexp.MustCompile(`(?i)Microsoft SQL Server`),
	regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)OLE DB.*SQL Server`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)SQLite/JDBCDriver`),
	regexp.MustCompile(`(?i)SQLite\.Exception`),
	regexp.MustCompile(`(?i)sqlite3.OperationalError`),
	regexp.MustCompile(`(?i)\bORA-[0-9]{4,5}`),
	regexp.MustCompile(`(?i)Oracle.*Driver`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
}

func matchSQLError(body string) string {
	for _, re := range sqlErrorSignatures {
		if loc := re.FindString(body); loc != "" {
			return loc
		}
	}

	return ""
}

type sqlInjectionCheck struct{}

func (sqlInjectionCheck) ID() string   { return "sqli-error" }
func (sqlInjectionCheck) Name() string { return "SQL Injection (error-based)" }

func (c sqlInjectionCheck) Run(sc *ScanContext) []Finding {
	// If the baseline already contains a SQL error, suppress to avoid false
	// positives from a pre-existing broken page.
	baselineHasErr := sc.Baseline != nil && matchSQLError(string(sc.Baseline.Body)) != ""
	if baselineHasErr {
		return nil
	}

	for _, payload := range []string{"'", "\"", "')", "';"} {
		res, req, err := sc.SendAppended(payload)
		if err != nil || res == nil {
			continue
		}

		if match := matchSQLError(string(res.Body)); match != "" {
			return []Finding{{
				Name:        c.Name(),
				Severity:    SeverityHigh,
				Confidence:  ConfidenceFirm,
				Payload:     payload,
				Evidence:    match,
				Description: "Appending a SQL meta-character to this parameter triggered a database error, indicating the value is concatenated into a SQL query without parameterization.",
				Remediation: "Use parameterized queries / prepared statements and validate input. Never build SQL by string concatenation.",
				Request:     req,
				Response:    res,
			}}
		}
	}

	return nil
}

// --- OS command injection (time-based) ------------------------------------

type commandInjectionCheck struct{}

func (commandInjectionCheck) ID() string   { return "cmdi-time" }
func (commandInjectionCheck) Name() string { return "OS Command Injection (time-based)" }

// CmdInjectionDelaySeconds is the delay (seconds) injected by the time-based
// payloads. It must be comfortably below Options.RequestTimeout. It is a var so
// tests can lower it for speed.
var CmdInjectionDelaySeconds = 7

func (c commandInjectionCheck) Run(sc *ScanContext) []Finding {
	delay := CmdInjectionDelaySeconds

	payloads := []string{
		fmt.Sprintf(";sleep %d", delay),
		fmt.Sprintf("|sleep %d", delay),
		fmt.Sprintf("`sleep %d`", delay),
		fmt.Sprintf("$(sleep %d)", delay),
		fmt.Sprintf("& ping -n %d 127.0.0.1 &", delay),
	}

	threshold := time.Duration(delay-1) * time.Second

	for _, payload := range payloads {
		res, req, err := sc.SendAppended(payload)
		if err != nil || res == nil {
			continue
		}

		if res.Duration < threshold {
			continue
		}

		// Verify: a non-delaying control payload should return quickly. This
		// guards against slow endpoints producing false positives.
		ctrl := strings.Replace(payload, fmt.Sprintf("%d", delay), "0", 1)
		ctrlRes, _, err := sc.SendAppended(ctrl)
		if err != nil || ctrlRes == nil {
			continue
		}

		if ctrlRes.Duration < threshold {
			return []Finding{{
				Name:       c.Name(),
				Severity:   SeverityCritical,
				Confidence: ConfidenceFirm,
				Payload:    payload,
				Evidence: fmt.Sprintf("Injected delay payload responded in %s; control payload responded in %s.",
					res.Duration.Round(time.Millisecond), ctrlRes.Duration.Round(time.Millisecond)),
				Description: "A time-delay command payload measurably slowed the response, indicating the parameter is passed to an OS shell.",
				Remediation: "Avoid invoking shells with user input. Use native library calls or strict allow-list argument APIs that don't spawn a shell.",
				Request:     req,
				Response:    res,
			}}
		}
	}

	return nil
}

// --- Path traversal / LFI -------------------------------------------------

var (
	unixPasswdRe = regexp.MustCompile(`root:.*:0:0:`)
	winIniRe     = regexp.MustCompile(`(?i)\[(fonts|extensions|mci extensions)\]`)
)

type pathTraversalCheck struct{}

func (pathTraversalCheck) ID() string   { return "path-traversal" }
func (pathTraversalCheck) Name() string { return "Path Traversal / Local File Inclusion" }

func (c pathTraversalCheck) Run(sc *ScanContext) []Finding {
	payloads := []string{
		"../../../../../../../../etc/passwd",
		"....//....//....//....//etc/passwd",
		"..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd",
		"/etc/passwd",
		"..\\..\\..\\..\\..\\..\\windows\\win.ini",
	}

	for _, payload := range payloads {
		res, req, err := sc.Send(payload)
		if err != nil || res == nil {
			continue
		}

		body := string(res.Body)

		if loc := unixPasswdRe.FindString(body); loc != "" {
			return []Finding{{
				Name:        c.Name(),
				Severity:    SeverityHigh,
				Confidence:  ConfidenceFirm,
				Payload:     payload,
				Evidence:    loc,
				Description: "A directory-traversal sequence returned the contents of /etc/passwd, confirming arbitrary local file read.",
				Remediation: "Resolve and canonicalize paths, reject traversal sequences, and serve files from a fixed allow-listed directory.",
				Request:     req,
				Response:    res,
			}}
		}

		if winIniRe.MatchString(body) && strings.Contains(strings.ToLower(payload), "win.ini") {
			return []Finding{{
				Name:        c.Name(),
				Severity:    SeverityHigh,
				Confidence:  ConfidenceFirm,
				Payload:     payload,
				Evidence:    winIniRe.FindString(body),
				Description: "A directory-traversal sequence returned the contents of windows\\win.ini, confirming arbitrary local file read.",
				Remediation: "Resolve and canonicalize paths, reject traversal sequences, and serve files from a fixed allow-listed directory.",
				Request:     req,
				Response:    res,
			}}
		}
	}

	return nil
}

// --- Open redirect --------------------------------------------------------

type openRedirectCheck struct{}

func (openRedirectCheck) ID() string   { return "open-redirect" }
func (openRedirectCheck) Name() string { return "Open Redirect" }

const openRedirectHost = "hetty-redirect.example"

func (c openRedirectCheck) Run(sc *ScanContext) []Finding {
	payloads := []string{
		"https://" + openRedirectHost + "/",
		"//" + openRedirectHost + "/",
		"https:/" + openRedirectHost,
		"https://" + openRedirectHost + "%2f%2f",
	}

	for _, payload := range payloads {
		res, req, err := sc.Send(payload)
		if err != nil || res == nil {
			continue
		}

		if res.StatusCode < 300 || res.StatusCode >= 400 {
			continue
		}

		loc := res.Header.Get("Location")
		if loc == "" {
			continue
		}

		if redirectsTo(loc, openRedirectHost) {
			return []Finding{{
				Name:        c.Name(),
				Severity:    SeverityMedium,
				Confidence:  ConfidenceFirm,
				Payload:     payload,
				Evidence:    "Location: " + loc,
				Description: "The application issued a redirect to an attacker-controlled host derived from a request parameter, enabling phishing and OAuth token theft.",
				Remediation: "Redirect only to a server-side allow-list of paths/hosts; never reflect a user-supplied URL into the Location header.",
				Request:     req,
				Response:    res,
			}}
		}
	}

	return nil
}

func redirectsTo(location, host string) bool {
	if u, err := url.Parse(location); err == nil && strings.EqualFold(u.Hostname(), host) {
		return true
	}

	// Catch scheme-relative and malformed variants that browsers still follow.
	trimmed := strings.TrimLeft(location, "/\\")

	return strings.HasPrefix(strings.ToLower(trimmed), strings.ToLower(host))
}

// --- Server-Side Template Injection ---------------------------------------

type sstiCheck struct{}

func (sstiCheck) ID() string   { return "ssti" }
func (sstiCheck) Name() string { return "Server-Side Template Injection (SSTI)" }

func (c sstiCheck) Run(sc *ScanContext) []Finding {
	// Use distinctive factors so the product is unlikely to appear by chance.
	const a, b = 1287, 1299
	product := fmt.Sprintf("%d", a*b) // 1671813

	payloads := []string{
		fmt.Sprintf("{{%d*%d}}", a, b),
		fmt.Sprintf("${%d*%d}", a, b),
		fmt.Sprintf("#{%d*%d}", a, b),
		fmt.Sprintf("${{%d*%d}}", a, b),
		fmt.Sprintf("<%%= %d*%d %%>", a, b),
		fmt.Sprintf("*{%d*%d}", a, b),
	}

	for _, payload := range payloads {
		res, req, err := sc.Send(payload)
		if err != nil || res == nil {
			continue
		}

		body := string(res.Body)
		// The literal payload must NOT be present (that would just be a
		// reflection), but the evaluated product must be.
		if strings.Contains(body, product) && !strings.Contains(body, payload) {
			return []Finding{{
				Name:        c.Name(),
				Severity:    SeverityHigh,
				Confidence:  ConfidenceFirm,
				Payload:     payload,
				Evidence:    snippet(body, product, 120),
				Description: "A template expression supplied in this parameter was evaluated server-side, which commonly leads to remote code execution.",
				Remediation: "Never pass user input into template engines as template source. Use a sandbox or treat input strictly as data.",
				Request:     req,
				Response:    res,
			}}
		}
	}

	return nil
}

// --- CRLF / HTTP response header injection ---------------------------------

type crlfInjectionCheck struct{}

func (crlfInjectionCheck) ID() string   { return "crlf-injection" }
func (crlfInjectionCheck) Name() string { return "CRLF / HTTP Header Injection" }

func (c crlfInjectionCheck) Run(sc *ScanContext) []Finding {
	nonce := randToken(5)
	injected := "Hz-Inject"
	// Raw CR LF; when applied to a query/form value it is percent-encoded, and a
	// vulnerable endpoint that decodes it will split the header.
	payload := "\r\n" + injected + ": " + nonce

	res, req, err := sc.Send(payload)
	if err != nil || res == nil {
		return nil
	}

	if got := res.Header.Get(injected); got == nonce {
		return []Finding{{
			Name:        c.Name(),
			Severity:    SeverityMedium,
			Confidence:  ConfidenceFirm,
			Payload:     payload,
			Evidence:    fmt.Sprintf("%s: %s", injected, got),
			Description: "A CR/LF sequence in this parameter was reflected into the response headers, allowing header injection, cache poisoning, or response splitting.",
			Remediation: "Strip CR/LF characters from any user input used to construct HTTP headers; rely on the framework's header API rather than raw writes.",
			Request:     req,
			Response:    res,
		}}
	}

	return nil
}
