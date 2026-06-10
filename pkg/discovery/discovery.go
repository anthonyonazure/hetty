// Package discovery implements content discovery (forced browsing) — Hetty's
// analogue of dirb/gobuster/ffuf and Burp's "Discover content". It requests
// candidate paths from a wordlist against a seed URL, optionally appending
// extensions and recursing into discovered directories, and reports the paths
// that exist. Soft-404 calibration suppresses servers that answer 200 for
// everything.
package discovery

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dstotijn/hetty/pkg/ratelimit"
	"github.com/dstotijn/hetty/pkg/respfilter"
)

// Options configures a discovery run.
type Options struct {
	// Wordlist of candidate path segments. Empty falls back to CommonWordlist.
	Wordlist []string `json:"wordlist"`
	// Extensions to append to each word (e.g. ["php","bak"]). The bare word is
	// always tried too.
	Extensions []string `json:"extensions"`
	// MaxDepth bounds recursion into discovered directories (0 = no recursion).
	MaxDepth int `json:"maxDepth"`
	// Concurrency is the number of in-flight requests.
	Concurrency int `json:"concurrency"`
	// TimeoutMs is the per-request timeout.
	TimeoutMs int `json:"timeoutMs"`
	// RequestsPerSecond throttles the run (0 = unthrottled).
	RequestsPerSecond float64 `json:"requestsPerSecond"`
	// StatusExclude lists statuses treated as "not found" (default: 404).
	StatusExclude []int `json:"statusExclude"`
	// UserAgent overrides the default User-Agent.
	UserAgent string `json:"userAgent"`
	// Headers are extra request headers (e.g. an auth cookie).
	Headers map[string]string `json:"headers"`
	// Filter, when set, drops hits that don't match its ffuf-style rules.
	Filter *respfilter.Filter `json:"filter,omitempty"`
}

func (o Options) excluded(status int) bool {
	excl := o.StatusExclude
	if len(excl) == 0 {
		excl = []int{http.StatusNotFound}
	}
	for _, s := range excl {
		if s == status {
			return true
		}
	}
	return false
}

// Hit is a discovered path.
type Hit struct {
	URL         string `json:"url"`
	Status      int    `json:"status"`
	Length      int    `json:"length"`
	Depth       int    `json:"depth"`
	ContentType string `json:"contentType"`
	Redirect    string `json:"redirect,omitempty"`
}

// Result summarizes a discovery run.
type Result struct {
	Seed     string `json:"seed"`
	Hits     []Hit  `json:"hits"`
	Requests int    `json:"requests"`
}

// Engine runs content discovery.
type Engine struct {
	newClient func(timeout time.Duration) *http.Client
}

// New returns a discovery engine.
func New() *Engine {
	return &Engine{
		newClient: func(timeout time.Duration) *http.Client {
			return &http.Client{
				Timeout: timeout,
				CheckRedirect: func(req *http.Request, via []*http.Request) error {
					return http.ErrUseLastResponse
				},
			}
		},
	}
}

type probe struct {
	status int
	length int
	ctype  string
	loc    string
	body   []byte
	err    error
}

// Discover runs content discovery against seed.
func (e *Engine) Discover(ctx context.Context, seed string, opts Options) (Result, error) {
	base, err := url.Parse(seed)
	if err != nil {
		return Result{}, fmt.Errorf("discovery: invalid seed URL: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return Result{}, fmt.Errorf("discovery: seed URL must be absolute")
	}

	words := opts.Wordlist
	if len(words) == 0 {
		words = CommonWordlist
	}

	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := e.newClient(timeout)

	limiter := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: opts.RequestsPerSecond,
		MaxConcurrent:     opts.Concurrency,
	})

	r := &runner{
		engine:  e,
		client:  client,
		limiter: limiter,
		opts:    opts,
		words:   words,
		visited: make(map[string]struct{}),
	}

	if opts.Filter != nil {
		if err := opts.Filter.Compile(); err != nil {
			return Result{}, err
		}
		r.opts.Filter = opts.Filter
	}

	// Calibrate soft-404 at the seed directory.
	r.calibrate(ctx, base)

	hits := r.scanDir(ctx, base, 0)

	return Result{Seed: seed, Hits: hits, Requests: r.requestCount()}, nil
}

type runner struct {
	engine  *Engine
	client  *http.Client
	limiter *ratelimit.Limiter
	opts    Options
	words   []string

	mu       sync.Mutex
	visited  map[string]struct{}
	requests int

	// soft-404 calibration per directory base path.
	calMu sync.Mutex
	calib map[string]probe
}

func (r *runner) requestCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.requests
}

func (r *runner) markVisited(p string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.visited[p]; ok {
		return false
	}
	r.visited[p] = struct{}{}
	return true
}

func (r *runner) calibrate(ctx context.Context, dir *url.URL) {
	r.calMu.Lock()
	if r.calib == nil {
		r.calib = make(map[string]probe)
	}
	r.calMu.Unlock()

	// Request a path very unlikely to exist.
	u := *dir
	u.Path = joinPath(dir.Path, "hetty-nonexistent-7f3a9c2e")
	p := r.do(ctx, &u)

	r.calMu.Lock()
	r.calib[dir.Path] = p
	r.calMu.Unlock()
}

// isSoft404 reports whether p looks like the calibrated catch-all response for
// dir.
func (r *runner) isSoft404(dirPath string, p probe) bool {
	r.calMu.Lock()
	cal, ok := r.calib[dirPath]
	r.calMu.Unlock()
	if !ok || cal.err != nil {
		return false
	}
	if cal.status != p.status {
		return false
	}
	// Same status as the catch-all; treat near-equal length as a soft 404. The
	// tolerance is deliberately tight: hiding a real short page (false negative)
	// is worse than surfacing a near-miss for the user to dismiss.
	diff := cal.length - p.length
	if diff < 0 {
		diff = -diff
	}
	tol := cal.length / 50
	if tol < 4 {
		tol = 4
	}
	return diff <= tol
}

func (r *runner) candidates() []string {
	var out []string
	for _, w := range r.words {
		w = strings.TrimSpace(w)
		if w == "" || strings.HasPrefix(w, "#") {
			continue
		}
		out = append(out, w)
		for _, ext := range r.opts.Extensions {
			ext = strings.TrimPrefix(strings.TrimSpace(ext), ".")
			if ext != "" {
				out = append(out, w+"."+ext)
			}
		}
	}
	return out
}

func (r *runner) scanDir(ctx context.Context, dir *url.URL, depth int) []Hit {
	candidates := r.candidates()

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		hits     []Hit
		subdirs  []*url.URL
		subdirMu sync.Mutex
	)

	for _, word := range candidates {
		word := word
		u := *dir
		u.Path = joinPath(dir.Path, word)

		if !r.markVisited(u.String()) {
			continue
		}

		wg.Add(1)
		go func() {
			defer wg.Done()

			if ctx.Err() != nil {
				return
			}

			p := r.do(ctx, &u)
			if p.err != nil {
				return
			}
			if r.opts.excluded(p.status) {
				return
			}
			if r.isSoft404(dir.Path, p) {
				return
			}
			if r.opts.Filter != nil && r.opts.Filter.Active() &&
				!r.opts.Filter.Keep(p.status, p.length, respfilter.Words(p.body), respfilter.Lines(p.body), p.body) {
				return
			}

			hit := Hit{
				URL:         u.String(),
				Status:      p.status,
				Length:      p.length,
				Depth:       depth,
				ContentType: p.ctype,
				Redirect:    p.loc,
			}
			mu.Lock()
			hits = append(hits, hit)
			mu.Unlock()

			// Queue directory-like hits for recursion.
			if depth < r.opts.MaxDepth && looksLikeDir(word, p) {
				sub := *dir
				sub.Path = ensureTrailingSlash(joinPath(dir.Path, word))
				subdirMu.Lock()
				subdirs = append(subdirs, &sub)
				subdirMu.Unlock()
			}
		}()
	}
	wg.Wait()

	for _, sub := range subdirs {
		r.calibrate(ctx, sub)
		hits = append(hits, r.scanDir(ctx, sub, depth+1)...)
	}

	return hits
}

func (r *runner) do(ctx context.Context, u *url.URL) probe {
	release, err := r.limiter.Acquire(ctx)
	if err != nil {
		return probe{err: err}
	}
	defer release()

	r.mu.Lock()
	r.requests++
	r.mu.Unlock()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return probe{err: err}
	}
	if r.opts.UserAgent != "" {
		req.Header.Set("User-Agent", r.opts.UserAgent)
	}
	for k, v := range r.opts.Headers {
		req.Header.Set(k, v)
	}

	res, err := r.client.Do(req)
	if err != nil {
		return probe{err: err}
	}
	defer res.Body.Close()

	// Read the body (capped) so the length is accurate and the filter can match
	// on size/words/lines/regex.
	body, _ := io.ReadAll(io.LimitReader(res.Body, 2<<20))

	return probe{
		status: res.StatusCode,
		length: len(body),
		ctype:  res.Header.Get("Content-Type"),
		loc:    res.Header.Get("Location"),
		body:   body,
	}
}

func looksLikeDir(word string, p probe) bool {
	if strings.Contains(word, ".") {
		return false
	}
	// 2xx, 403 (exists but forbidden), or a redirect that appends a slash.
	if p.status == http.StatusForbidden {
		return true
	}
	if p.status >= 200 && p.status < 300 {
		return true
	}
	if (p.status == http.StatusMovedPermanently || p.status == http.StatusFound) &&
		strings.HasSuffix(strings.TrimRight(p.loc, "/")+"/", word+"/") {
		return true
	}
	return false
}

func joinPath(base, seg string) string {
	base = strings.TrimRight(base, "/")
	seg = strings.TrimLeft(seg, "/")
	if base == "" {
		return "/" + seg
	}
	return base + "/" + seg
}

func ensureTrailingSlash(p string) string {
	if strings.HasSuffix(p, "/") {
		return p
	}
	return p + "/"
}
