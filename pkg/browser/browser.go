// Package browser implements a JavaScript-rendering crawler. The static spider
// only parses server-returned HTML, so it misses endpoints that a single-page
// app builds at runtime. This crawler drives a headless Chrome (via chromedp),
// lets each page's JavaScript execute, and then extracts links and form actions
// from the rendered DOM — surfacing routes the static crawler never sees.
//
// Chrome must be installed for live crawling; the BFS and URL-handling logic is
// exercised independently of the browser in tests.
package browser

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/chromedp/chromedp"
)

// Options configures a render-crawl.
type Options struct {
	MaxDepth     int      `json:"maxDepth"`
	MaxPages     int      `json:"maxPages"`
	WaitMs       int      `json:"waitMs"` // settle time after navigation for JS to render
	TimeoutMs    int      `json:"timeoutMs"`
	SameHostOnly bool     `json:"sameHostOnly"`
	AllowedHosts []string `json:"allowedHosts"`
}

// Page is one rendered page.
type Page struct {
	URL   string   `json:"url"`
	Title string   `json:"title"`
	Depth int      `json:"depth"`
	Links []string `json:"links"`
	Error string   `json:"error,omitempty"`
}

// Result is the crawl output.
type Result struct {
	Seed  string   `json:"seed"`
	Pages []Page   `json:"pages"`
	URLs  []string `json:"urls"`
}

// visitFunc renders a single URL and returns its title and discovered links.
type visitFunc func(ctx context.Context, rawURL string, waitMs int) (title string, links []string, err error)

// Crawler performs JS-rendered crawls.
type Crawler struct {
	visit visitFunc
}

// New returns a render-crawler backed by headless Chrome.
func New() *Crawler {
	return &Crawler{visit: chromedpVisit}
}

// extractScript collects link-like URLs from the rendered DOM.
const extractScript = `JSON.stringify(
  Array.from(document.querySelectorAll('a[href]')).map(a => a.href)
    .concat(Array.from(document.querySelectorAll('form[action]')).map(f => f.action))
    .concat(Array.from(document.querySelectorAll('[data-href],[data-url]')).map(e => e.getAttribute('data-href') || e.getAttribute('data-url')))
)`

// chromedpVisit drives headless Chrome to render rawURL.
func chromedpVisit(ctx context.Context, rawURL string, waitMs int) (string, []string, error) {
	var title, raw string
	err := chromedp.Run(ctx,
		chromedp.Navigate(rawURL),
		chromedp.Sleep(time.Duration(waitMs)*time.Millisecond),
		chromedp.Title(&title),
		chromedp.Evaluate(extractScript, &raw),
	)
	if err != nil {
		return "", nil, err
	}
	var links []string
	_ = json.Unmarshal([]byte(raw), &links)
	return title, links, nil
}

// Crawl renders pages starting from seed, following links in scope.
func (c *Crawler) Crawl(ctx context.Context, seed string, opts Options) (Result, error) {
	defaults(&opts)

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx,
		append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.NoFirstRun, chromedp.NoDefaultBrowserCheck, chromedp.IgnoreCertErrors)...)
	defer cancelAlloc()

	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	defer cancelBrowser()

	if opts.TimeoutMs > 0 {
		var cancel context.CancelFunc
		browserCtx, cancel = context.WithTimeout(browserCtx, time.Duration(opts.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	return crawlWith(browserCtx, seed, opts, c.visit)
}

func defaults(o *Options) {
	if o.MaxPages <= 0 {
		o.MaxPages = 50
	}
	if o.WaitMs <= 0 {
		o.WaitMs = 1000
	}
}

// crawlWith runs the breadth-first crawl using the supplied visit function. It
// is browser-agnostic and exercised directly in tests.
func crawlWith(ctx context.Context, seed string, opts Options, visit visitFunc) (Result, error) {
	defaults(&opts)

	seedURL, err := url.Parse(seed)
	if err != nil || seedURL.Host == "" {
		return Result{}, errInvalidSeed
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

		var next []string
		for _, u := range current {
			if ctx.Err() != nil {
				return result, ctx.Err()
			}
			title, links, err := visit(ctx, u, opts.WaitMs)
			page := Page{URL: u, Title: title, Depth: depth}
			if err != nil {
				page.Error = err.Error()
			}

			for _, link := range links {
				abs := resolve(seedURL, link)
				if abs == "" {
					continue
				}
				key := normalize(abs)
				if visited[key] || !inScope(abs, seedURL, opts) {
					continue
				}
				visited[key] = true
				page.Links = append(page.Links, abs)
				next = append(next, abs)
			}

			result.Pages = append(result.Pages, page)
			result.URLs = append(result.URLs, u)
		}
		current = next
	}

	return result, nil
}

var errInvalidSeed = &crawlError{"browser: seed must be an absolute URL"}

type crawlError struct{ msg string }

func (e *crawlError) Error() string { return e.msg }

func resolve(base *url.URL, link string) string {
	link = strings.TrimSpace(link)
	if link == "" || strings.HasPrefix(link, "javascript:") || strings.HasPrefix(link, "mailto:") ||
		strings.HasPrefix(link, "tel:") || strings.HasPrefix(link, "#") || strings.HasPrefix(link, "data:") {
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

func normalize(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

func inScope(rawURL string, seed *url.URL, opts Options) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if opts.SameHostOnly && u.Host != seed.Host {
		return false
	}
	if len(opts.AllowedHosts) > 0 {
		for _, h := range opts.AllowedHosts {
			if u.Host == h {
				return true
			}
		}
		return false
	}
	return true
}
