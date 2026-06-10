// Package rules implements Hetty's Match & Replace feature: user-defined rules
// that rewrite parts of proxied requests and responses (request line, header
// block, or body) using literal or regular-expression matching. The Engine
// exposes proxy request/response middleware.
package rules

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/dstotijn/hetty/pkg/proxy"
)

// Part identifies which portion of a message a rule targets.
type Part string

const (
	PartRequestURL     Part = "request_url"
	PartRequestHeader  Part = "request_header"
	PartRequestBody    Part = "request_body"
	PartResponseHeader Part = "response_header"
	PartResponseBody   Part = "response_body"
)

// Rule is a single match-and-replace rule.
type Rule struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Part    Part   `json:"part"`
	Match   string `json:"match"`
	Replace string `json:"replace"`
	IsRegex bool   `json:"isRegex"`

	re *regexp.Regexp
}

func (r *Rule) compile() error {
	if r.IsRegex {
		re, err := regexp.Compile(r.Match)
		if err != nil {
			return fmt.Errorf("rules: rule %q has invalid regex: %w", r.ID, err)
		}
		r.re = re
	}
	return nil
}

// apply returns the transformed string and whether anything changed.
func (r *Rule) apply(s string) (string, bool) {
	if r.IsRegex {
		if r.re == nil || !r.re.MatchString(s) {
			return s, false
		}
		return r.re.ReplaceAllString(s, r.Replace), true
	}

	if r.Match == "" || !strings.Contains(s, r.Match) {
		return s, false
	}
	return strings.ReplaceAll(s, r.Match, r.Replace), true
}

// Engine holds a compiled, ordered set of rules and applies them as proxy
// middleware.
type Engine struct {
	mu    sync.RWMutex
	rules []Rule
}

// NewEngine returns an empty Engine.
func NewEngine() *Engine { return &Engine{} }

// SetRules validates and installs the rule set, replacing any existing rules.
func (e *Engine) SetRules(rules []Rule) error {
	compiled := make([]Rule, len(rules))
	for i := range rules {
		r := rules[i]
		if err := r.compile(); err != nil {
			return err
		}
		compiled[i] = r
	}

	e.mu.Lock()
	e.rules = compiled
	e.mu.Unlock()

	return nil
}

// Rules returns a copy of the installed rules.
func (e *Engine) Rules() []Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()

	out := make([]Rule, len(e.rules))
	copy(out, e.rules)

	return out
}

func (e *Engine) rulesFor(parts ...Part) []Rule {
	want := map[Part]bool{}
	for _, p := range parts {
		want[p] = true
	}

	e.mu.RLock()
	defer e.mu.RUnlock()

	var out []Rule
	for _, r := range e.rules {
		if r.Enabled && want[r.Part] {
			out = append(out, r)
		}
	}

	return out
}

// RequestModifier implements proxy.RequestModifyMiddleware.
func (e *Engine) RequestModifier(next proxy.RequestModifyFunc) proxy.RequestModifyFunc {
	return func(req *http.Request) {
		next(req)
		e.applyRequest(req)
	}
}

// ResponseModifier implements proxy.ResponseModifyMiddleware.
func (e *Engine) ResponseModifier(next proxy.ResponseModifyFunc) proxy.ResponseModifyFunc {
	return func(res *http.Response) error {
		if err := next(res); err != nil {
			return err
		}
		e.applyResponse(res)
		return nil
	}
}

func (e *Engine) applyRequest(req *http.Request) {
	// URL rules.
	for _, r := range e.rulesFor(PartRequestURL) {
		if out, changed := r.apply(req.URL.String()); changed {
			if u, err := url.Parse(out); err == nil {
				req.URL = u
			}
		}
	}

	// Header block rules.
	if headerRules := e.rulesFor(PartRequestHeader); len(headerRules) > 0 {
		block := headerBlock(req.Header)
		changed := false
		for _, r := range headerRules {
			if out, did := r.apply(block); did {
				block = out
				changed = true
			}
		}
		if changed {
			req.Header = parseHeaderBlock(block)
		}
	}

	// Body rules.
	if bodyRules := e.rulesFor(PartRequestBody); len(bodyRules) > 0 && req.Body != nil {
		body, err := io.ReadAll(req.Body)
		if err == nil {
			s := string(body)
			changed := false
			for _, r := range bodyRules {
				if out, did := r.apply(s); did {
					s = out
					changed = true
				}
			}
			newBody := []byte(s)
			req.Body = io.NopCloser(bytes.NewReader(newBody))
			if changed {
				req.ContentLength = int64(len(newBody))
				req.Header.Del("Content-Length")
			}
		}
	}
}

func (e *Engine) applyResponse(res *http.Response) {
	if headerRules := e.rulesFor(PartResponseHeader); len(headerRules) > 0 {
		block := headerBlock(res.Header)
		changed := false
		for _, r := range headerRules {
			if out, did := r.apply(block); did {
				block = out
				changed = true
			}
		}
		if changed {
			res.Header = parseHeaderBlock(block)
		}
	}

	if bodyRules := e.rulesFor(PartResponseBody); len(bodyRules) > 0 && res.Body != nil {
		body, err := io.ReadAll(res.Body)
		if err == nil {
			s := string(body)
			changed := false
			for _, r := range bodyRules {
				if out, did := r.apply(s); did {
					s = out
					changed = true
				}
			}
			newBody := []byte(s)
			res.Body = io.NopCloser(bytes.NewReader(newBody))
			if changed {
				res.ContentLength = int64(len(newBody))
				res.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBody)))
			}
		}
	}
}

// headerBlock serializes headers into a canonical "Name: Value\n" block with
// keys sorted for deterministic matching.
func headerBlock(h http.Header) string {
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		for _, v := range h[k] {
			b.WriteString(k)
			b.WriteString(": ")
			b.WriteString(v)
			b.WriteByte('\n')
		}
	}

	return b.String()
}

// parseHeaderBlock parses a "Name: Value" block back into an http.Header.
func parseHeaderBlock(block string) http.Header {
	h := http.Header{}
	for _, line := range strings.Split(block, "\n") {
		line = strings.TrimRight(line, "\r")
		if line == "" {
			continue
		}
		idx := strings.Index(line, ":")
		if idx <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:idx])
		value := strings.TrimSpace(line[idx+1:])
		if name != "" {
			h.Add(name, value)
		}
	}

	return h
}
