// Package template implements a nuclei-style templated vulnerability scanner: a
// compact, compatible subset of the nuclei YAML format so Hetty can consume the
// large ecosystem of community detection templates. A template declares one or
// more requests and a set of matchers (status / word / regex over the response
// body, headers or both); a target that satisfies the matchers produces a
// finding.
package template

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v2"

	"github.com/dstotijn/hetty/pkg/ratelimit"
)

// Template is a parsed detection template.
type Template struct {
	ID       string    `yaml:"id" json:"id"`
	Info     Info      `yaml:"info" json:"info"`
	Requests []Request `yaml:"requests" json:"-"`
	// HTTP is the newer nuclei key for the request list; either is accepted.
	HTTP []Request `yaml:"http" json:"-"`
}

// Info is template metadata.
type Info struct {
	Name        string `yaml:"name" json:"name"`
	Author      string `yaml:"author" json:"author,omitempty"`
	Severity    string `yaml:"severity" json:"severity"`
	Description string `yaml:"description" json:"description,omitempty"`
	Tags        string `yaml:"tags" json:"tags,omitempty"`
}

// Request is one HTTP request with its matchers.
type Request struct {
	Method            string            `yaml:"method"`
	Path              []string          `yaml:"path"`
	Headers           map[string]string `yaml:"headers"`
	Body              string            `yaml:"body"`
	MatchersCondition string            `yaml:"matchers-condition"` // "and" | "or" (default "or")
	Matchers          []Matcher         `yaml:"matchers"`
}

// Matcher is a single condition over a response.
type Matcher struct {
	Type      string   `yaml:"type"`      // status | word | regex
	Part      string   `yaml:"part"`      // body | header | all (default body)
	Status    []int    `yaml:"status"`
	Words     []string `yaml:"words"`
	Regex     []string `yaml:"regex"`
	Condition string   `yaml:"condition"` // "and" | "or" among words/regex (default "or")
	Negative  bool     `yaml:"negative"`
}

func (t *Template) requests() []Request {
	if len(t.Requests) > 0 {
		return t.Requests
	}
	return t.HTTP
}

// Parse decodes a single template from YAML.
func Parse(data []byte) (*Template, error) {
	var t Template
	if err := yaml.Unmarshal(data, &t); err != nil {
		return nil, fmt.Errorf("template: parse: %w", err)
	}
	if t.ID == "" {
		return nil, fmt.Errorf("template: missing id")
	}
	if len(t.requests()) == 0 {
		return nil, fmt.Errorf("template %q: no requests", t.ID)
	}
	return &t, nil
}

// LoadDir loads every .yaml/.yml template under dir (recursively). Parse errors
// are skipped (reported in errs) so one bad template doesn't abort the load.
func LoadDir(dir string) (templates []*Template, errs []error) {
	_ = filepath.Walk(dir, func(path string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext != ".yaml" && ext != ".yml" {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			errs = append(errs, err)
			return nil
		}
		t, err := Parse(data)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", filepath.Base(path), err))
			return nil
		}
		templates = append(templates, t)
		return nil
	})
	return templates, errs
}

// Result is a template that matched a target.
type Result struct {
	TemplateID  string `json:"templateId"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	MatchedURL  string `json:"matchedUrl"`
	Description string `json:"description,omitempty"`
}

// Engine runs templates against targets.
type Engine struct {
	newClient func(timeout time.Duration) *http.Client
}

// New returns a template engine.
func New() *Engine {
	return &Engine{
		newClient: func(timeout time.Duration) *http.Client {
			return &http.Client{
				Timeout: timeout,
				//nolint:gosec
				Transport: &http.Transport{
					Proxy:               http.ProxyFromEnvironment,
					DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
					TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
					TLSHandshakeTimeout: 10 * time.Second,
				},
				CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
			}
		},
	}
}

// Options configures a run.
type Options struct {
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	TimeoutMs         int     `json:"timeoutMs"`
}

// Run evaluates templates against the target base URL, returning matches.
func (e *Engine) Run(ctx context.Context, target string, templates []*Template, opts Options) ([]Result, error) {
	target = strings.TrimRight(target, "/")
	if !strings.HasPrefix(target, "http://") && !strings.HasPrefix(target, "https://") {
		return nil, fmt.Errorf("template: target must be an absolute http(s) URL")
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	client := e.newClient(timeout)
	limiter := ratelimit.New(ratelimit.Config{RequestsPerSecond: opts.RequestsPerSecond})

	var results []Result
	for _, t := range templates {
		if matched, url := e.evalTemplate(ctx, client, limiter, target, t); matched {
			results = append(results, Result{
				TemplateID:  t.ID,
				Name:        t.Info.Name,
				Severity:    t.Info.Severity,
				MatchedURL:  url,
				Description: t.Info.Description,
			})
		}
	}
	return results, nil
}

func (e *Engine) evalTemplate(ctx context.Context, client *http.Client, limiter *ratelimit.Limiter, target string, t *Template) (bool, string) {
	for _, req := range t.requests() {
		paths := req.Path
		if len(paths) == 0 {
			paths = []string{"{{BaseURL}}"}
		}
		for _, p := range paths {
			url := substitute(p, target)
			if release, err := limiter.Acquire(ctx); err == nil {
				ok, matchURL := e.sendAndMatch(ctx, client, req, url)
				release()
				if ok {
					return true, matchURL
				}
			}
		}
	}
	return false, ""
}

func (e *Engine) sendAndMatch(ctx context.Context, client *http.Client, req Request, url string) (bool, string) {
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}
	var bodyReader io.Reader
	if req.Body != "" {
		bodyReader = strings.NewReader(req.Body)
	}
	httpReq, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return false, ""
	}
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	res, err := client.Do(httpReq)
	if err != nil {
		return false, ""
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 4<<20))

	if matchRequest(req, res, body) {
		return true, url
	}
	return false, ""
}

func matchRequest(req Request, res *http.Response, body []byte) bool {
	if len(req.Matchers) == 0 {
		return false
	}
	andCond := strings.EqualFold(req.MatchersCondition, "and")
	for _, m := range req.Matchers {
		ok := matchOne(m, res, body)
		if m.Negative {
			ok = !ok
		}
		if andCond && !ok {
			return false
		}
		if !andCond && ok {
			return true
		}
	}
	return andCond // and => all passed; or => none passed
}

func matchOne(m Matcher, res *http.Response, body []byte) bool {
	switch strings.ToLower(m.Type) {
	case "status":
		for _, s := range m.Status {
			if res.StatusCode == s {
				return true
			}
		}
		return false
	case "word":
		hay := part(m.Part, res, body)
		return matchWords(m.Words, hay, strings.EqualFold(m.Condition, "and"))
	case "regex":
		hay := part(m.Part, res, body)
		return matchRegex(m.Regex, hay, strings.EqualFold(m.Condition, "and"))
	default:
		return false
	}
}

func part(p string, res *http.Response, body []byte) string {
	switch strings.ToLower(p) {
	case "header", "headers":
		return headerString(res)
	case "all":
		return headerString(res) + "\n" + string(body)
	default: // body
		return string(body)
	}
}

func headerString(res *http.Response) string {
	var sb strings.Builder
	_ = res.Header.Write(&sb)
	return sb.String()
}

func matchWords(words []string, hay string, and bool) bool {
	if len(words) == 0 {
		return false
	}
	for _, w := range words {
		hit := strings.Contains(hay, w)
		if and && !hit {
			return false
		}
		if !and && hit {
			return true
		}
	}
	return and
}

func matchRegex(exprs []string, hay string, and bool) bool {
	if len(exprs) == 0 {
		return false
	}
	for _, expr := range exprs {
		re, err := regexp.Compile(expr)
		if err != nil {
			if and {
				return false
			}
			continue
		}
		hit := re.MatchString(hay)
		if and && !hit {
			return false
		}
		if !and && hit {
			return true
		}
	}
	return and
}

func substitute(path, target string) string {
	if strings.Contains(path, "{{BaseURL}}") || strings.Contains(path, "{{RootURL}}") {
		path = strings.ReplaceAll(path, "{{BaseURL}}", target)
		path = strings.ReplaceAll(path, "{{RootURL}}", target)
		return path
	}
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	return target + "/" + strings.TrimLeft(path, "/")
}
