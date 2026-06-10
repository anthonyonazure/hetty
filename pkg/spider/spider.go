// Package spider implements Hetty's crawler: a breadth-first web crawler that
// discovers reachable URLs from a seed by extracting links from HTML responses,
// constrained by scope, depth, and page limits. The discovered URLs feed the
// active scanner for crawl-and-audit workflows.
package spider

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dstotijn/hetty/pkg/ratelimit"
)

// Options configures a crawl.
type Options struct {
	MaxDepth     int      `json:"maxDepth"`
	MaxPages     int      `json:"maxPages"`
	Concurrency  int      `json:"concurrency"`
	TimeoutMs    int      `json:"timeoutMs"`
	SameHostOnly bool     `json:"sameHostOnly"`
	AllowedHosts []string `json:"allowedHosts"`
	UserAgent    string   `json:"userAgent"`
	// RequestsPerSecond throttles the crawl (0 = unthrottled). Combined with any
	// engine-wide limiter.
	RequestsPerSecond float64 `json:"requestsPerSecond"`
}

// DefaultOptions returns sensible crawl defaults.
func DefaultOptions() Options {
	return Options{
		MaxDepth:     2,
		MaxPages:     100,
		Concurrency:  8,
		TimeoutMs:    10000,
		SameHostOnly: true,
		UserAgent:    "Hetty-Spider/1.0",
	}
}

// Page is a single crawled resource.
type Page struct {
	URL    string   `json:"url"`
	Status int      `json:"status"`
	Depth  int      `json:"depth"`
	Type   string   `json:"contentType"`
	Links  []string `json:"links"`
	Error  string   `json:"error,omitempty"`
}

// Result is the outcome of a crawl.
type Result struct {
	Seed  string   `json:"seed"`
	Pages []Page   `json:"pages"`
	URLs  []string `json:"urls"`
}

var linkRe = regexp.MustCompile(`(?i)(?:href|src|action)\s*=\s*["']([^"'#]+)["']`)

// Crawler performs crawls.
type Crawler struct {
	newClient func(timeout time.Duration) *http.Client
	limiter   *ratelimit.Limiter
}

// New returns a new Crawler.
func New() *Crawler {
	return &Crawler{newClient: defaultClient}
}

// SetLimiter installs an engine-wide rate limiter, applied in addition to any
// per-crawl rate.
func (c *Crawler) SetLimiter(l *ratelimit.Limiter) {
	c.limiter = l
}

func defaultClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
			//nolint:gosec
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

// Crawl runs a breadth-first crawl from the seed URL.
func (c *Crawler) Crawl(ctx context.Context, seed string, opts Options) (Result, error) {
	if opts.MaxPages <= 0 {
		opts.MaxPages = 100
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	timeout := time.Duration(opts.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	client := c.newClient(timeout)

	var runLimiter *ratelimit.Limiter
	if opts.RequestsPerSecond > 0 {
		runLimiter = ratelimit.New(ratelimit.Config{RequestsPerSecond: opts.RequestsPerSecond})
	}

	seedURL, err := url.Parse(seed)
	if err != nil {
		return Result{}, err
	}

	result := Result{Seed: seed}
	visited := map[string]bool{normalize(seed): true}
	current := []string{seed}

	for depth := 0; depth <= opts.MaxDepth && len(result.Pages) < opts.MaxPages; depth++ {
		if len(current) == 0 {
			break
		}

		budget := opts.MaxPages - len(result.Pages)
		if budget < len(current) {
			current = current[:budget]
		}

		pages := c.fetchLevel(ctx, client, current, depth, opts, runLimiter)

		var next []string
		for _, p := range pages {
			result.Pages = append(result.Pages, p)
			result.URLs = append(result.URLs, p.URL)

			for _, link := range p.Links {
				abs := resolve(seedURL, link)
				if abs == "" {
					continue
				}
				key := normalize(abs)
				if visited[key] {
					continue
				}
				if !inScope(abs, seedURL, opts) {
					continue
				}
				visited[key] = true
				next = append(next, abs)
			}
		}

		current = next
	}

	return result, nil
}

func (c *Crawler) fetchLevel(ctx context.Context, client *http.Client, urls []string, depth int, opts Options, runLimiter *ratelimit.Limiter) []Page {
	pages := make([]Page, len(urls))
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup

	for i, u := range urls {
		i, u := i, u
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			pages[i] = c.fetch(ctx, client, u, depth, opts, runLimiter)
		}()
	}
	wg.Wait()

	return pages
}

func (c *Crawler) fetch(ctx context.Context, client *http.Client, u string, depth int, opts Options, runLimiter *ratelimit.Limiter) Page {
	page := Page{URL: u, Depth: depth}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		page.Error = err.Error()
		return page
	}
	if opts.UserAgent != "" {
		req.Header.Set("User-Agent", opts.UserAgent)
	}

	// Rate limiting: engine-wide cap, then any per-crawl cap (both may be nil).
	releaseEngine, err := c.limiter.Acquire(ctx)
	if err != nil {
		page.Error = err.Error()
		return page
	}
	defer releaseEngine()

	releaseRun, err := runLimiter.Acquire(ctx)
	if err != nil {
		page.Error = err.Error()
		return page
	}
	defer releaseRun()

	res, err := client.Do(req)
	if err != nil {
		page.Error = err.Error()
		return page
	}
	defer res.Body.Close()

	page.Status = res.StatusCode
	page.Type = res.Header.Get("Content-Type")

	if !strings.Contains(strings.ToLower(page.Type), "html") {
		return page
	}

	body, err := io.ReadAll(io.LimitReader(res.Body, 4<<20))
	if err != nil {
		page.Error = err.Error()
		return page
	}

	for _, m := range linkRe.FindAllStringSubmatch(string(body), -1) {
		page.Links = append(page.Links, m[1])
	}

	return page
}

func resolve(base *url.URL, link string) string {
	link = strings.TrimSpace(link)
	if link == "" || strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") || strings.HasPrefix(link, "data:") || strings.HasPrefix(link, "tel:") {
		return ""
	}
	u, err := url.Parse(link)
	if err != nil {
		return ""
	}
	abs := base.ResolveReference(u)
	if abs.Scheme != "http" && abs.Scheme != "https" {
		return ""
	}
	abs.Fragment = ""
	return abs.String()
}

func inScope(rawURL string, seed *url.URL, opts Options) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if len(opts.AllowedHosts) > 0 {
		for _, h := range opts.AllowedHosts {
			if strings.EqualFold(u.Hostname(), h) {
				return true
			}
		}
		return false
	}
	if opts.SameHostOnly {
		return strings.EqualFold(u.Hostname(), seed.Hostname())
	}
	return true
}

func normalize(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	s := u.String()
	return strings.TrimRight(s, "/")
}
