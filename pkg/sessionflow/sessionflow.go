// Package sessionflow runs login macros: an ordered sequence of HTTP requests
// sharing a cookie jar, extracting variables (CSRF tokens, bearer tokens,
// session cookies) along the way. The result can be turned into a session
// profile so the scanner / intruder / sender stay authenticated — the
// equivalent of Burp's session-handling rules and macros.
package sessionflow

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"regexp"
	"strings"
	"time"
)

// Header is a request/response header pair.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// Step is one request in the macro. URL, header values, and body may reference
// previously extracted variables with {{name}}.
type Step struct {
	Method  string   `json:"method"`
	URL     string   `json:"url"`
	Headers []Header `json:"headers"`
	Body    string   `json:"body"`
}

// Extractor pulls a value out of a step's response into a named variable.
type Extractor struct {
	Name    string `json:"name"`    // variable name
	Source  string `json:"source"`  // "header" | "cookie" | "body"
	Key     string `json:"key"`     // header/cookie name (header & cookie sources)
	Pattern string `json:"pattern"` // regex with one capture group (body source; optional for header)
}

// Macro is a named login sequence.
type Macro struct {
	Name       string      `json:"name"`
	Steps      []Step      `json:"steps"`
	Extractors []Extractor `json:"extractors"`
}

// StepResult records the outcome of a single step.
type StepResult struct {
	URL    string `json:"url"`
	Status int    `json:"status"`
	Error  string `json:"error,omitempty"`
}

// Result is the outcome of running a macro.
type Result struct {
	Vars    map[string]string `json:"vars"`
	Cookies []Header          `json:"cookies"`
	Steps   []StepResult      `json:"steps"`
}

// Engine runs macros.
type Engine struct {
	transport http.RoundTripper
	timeout   time.Duration
}

// New returns a sessionflow engine using the default transport.
func New() *Engine {
	return &Engine{transport: http.DefaultTransport, timeout: 15 * time.Second}
}

// SetTransport overrides the HTTP transport (e.g. to route through an upstream
// proxy). nil resets to the default.
func (e *Engine) SetTransport(rt http.RoundTripper) {
	if rt == nil {
		rt = http.DefaultTransport
	}
	e.transport = rt
}

// Run executes the macro and returns the extracted variables and the resulting
// cookie jar contents (keyed to the first step's host).
func (e *Engine) Run(ctx context.Context, m Macro) (Result, error) {
	if len(m.Steps) == 0 {
		return Result{}, fmt.Errorf("sessionflow: macro %q has no steps", m.Name)
	}

	jar, err := cookiejar.New(nil)
	if err != nil {
		return Result{}, err
	}
	client := &http.Client{Transport: e.transport, Jar: jar, Timeout: e.timeout}

	res := Result{Vars: map[string]string{}}

	for _, step := range m.Steps {
		method := step.Method
		if method == "" {
			method = http.MethodGet
		}
		url := substitute(step.URL, res.Vars)

		var bodyReader io.Reader
		if step.Body != "" {
			bodyReader = strings.NewReader(substitute(step.Body, res.Vars))
		}

		req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
		if err != nil {
			res.Steps = append(res.Steps, StepResult{URL: url, Error: err.Error()})
			return res, fmt.Errorf("sessionflow: build request for %q: %w", url, err)
		}
		for _, h := range step.Headers {
			req.Header.Set(h.Name, substitute(h.Value, res.Vars))
		}

		httpRes, err := client.Do(req)
		if err != nil {
			res.Steps = append(res.Steps, StepResult{URL: url, Error: err.Error()})
			return res, fmt.Errorf("sessionflow: request to %q failed: %w", url, err)
		}

		body, _ := io.ReadAll(io.LimitReader(httpRes.Body, 4<<20))
		httpRes.Body.Close()

		res.Steps = append(res.Steps, StepResult{URL: url, Status: httpRes.StatusCode})

		if err := applyExtractors(m.Extractors, httpRes, body, res.Vars); err != nil {
			return res, err
		}
	}

	// Collect the cookie jar for the first step's host.
	if first, err := http.NewRequest(http.MethodGet, substitute(m.Steps[0].URL, res.Vars), nil); err == nil {
		for _, ck := range jar.Cookies(first.URL) {
			res.Cookies = append(res.Cookies, Header{Name: ck.Name, Value: ck.Value})
		}
	}

	return res, nil
}

func applyExtractors(extractors []Extractor, res *http.Response, body []byte, vars map[string]string) error {
	for _, ex := range extractors {
		switch ex.Source {
		case "header":
			val := res.Header.Get(ex.Key)
			if ex.Pattern != "" {
				re, err := regexp.Compile(ex.Pattern)
				if err != nil {
					return fmt.Errorf("sessionflow: extractor %q: %w", ex.Name, err)
				}
				if m := re.FindStringSubmatch(val); len(m) > 1 {
					val = m[1]
				} else {
					continue
				}
			}
			vars[ex.Name] = val
		case "cookie":
			for _, ck := range res.Cookies() {
				if ck.Name == ex.Key {
					vars[ex.Name] = ck.Value
					break
				}
			}
		case "body":
			if ex.Pattern == "" {
				return fmt.Errorf("sessionflow: body extractor %q needs a pattern", ex.Name)
			}
			re, err := regexp.Compile(ex.Pattern)
			if err != nil {
				return fmt.Errorf("sessionflow: extractor %q: %w", ex.Name, err)
			}
			if m := re.FindSubmatch(body); len(m) > 1 {
				vars[ex.Name] = string(m[1])
			}
		default:
			return fmt.Errorf("sessionflow: extractor %q has unknown source %q (want header|cookie|body)", ex.Name, ex.Source)
		}
	}
	return nil
}

var varRe = regexp.MustCompile(`\{\{(\w+)\}\}`)

func substitute(s string, vars map[string]string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		name := varRe.FindStringSubmatch(m)[1]
		if v, ok := vars[name]; ok {
			return v
		}
		return m
	})
}
