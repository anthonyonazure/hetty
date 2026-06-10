package browser

import (
	"context"
	"net/url"
	"testing"
)

// fakeSite maps a URL to the links its (rendered) page exposes.
func fakeVisit(site map[string][]string) visitFunc {
	return func(ctx context.Context, rawURL string, waitMs int) (string, []string, error) {
		return "Title of " + rawURL, site[rawURL], nil
	}
}

func TestCrawlWithDiscoversRenderedLinks(t *testing.T) {
	site := map[string][]string{
		"https://app.test/":          {"https://app.test/dashboard", "/profile", "https://other.test/x"},
		"https://app.test/dashboard": {"https://app.test/dashboard/settings"},
		"https://app.test/profile":   {},
	}

	res, err := crawlWith(context.Background(), "https://app.test/", Options{
		MaxDepth: 2, MaxPages: 50, SameHostOnly: true,
	}, fakeVisit(site))
	if err != nil {
		t.Fatal(err)
	}

	urls := map[string]bool{}
	for _, u := range res.URLs {
		urls[u] = true
	}
	// Same-host pages should be crawled; the off-host link must be excluded.
	for _, want := range []string{"https://app.test/", "https://app.test/dashboard", "https://app.test/profile"} {
		if !urls[want] {
			t.Errorf("did not crawl %s; got %v", want, res.URLs)
		}
	}
	for _, u := range res.URLs {
		if u == "https://other.test/x" {
			t.Error("off-host URL should not be crawled with SameHostOnly")
		}
	}
}

func TestCrawlWithRespectsMaxPages(t *testing.T) {
	site := map[string][]string{
		"https://app.test/": {"https://app.test/a", "https://app.test/b", "https://app.test/c"},
	}
	res, _ := crawlWith(context.Background(), "https://app.test/", Options{
		MaxDepth: 3, MaxPages: 2, SameHostOnly: true,
	}, fakeVisit(site))
	if len(res.Pages) > 2 {
		t.Errorf("crawled %d pages, want <= 2 (MaxPages)", len(res.Pages))
	}
}

func TestResolveAndScope(t *testing.T) {
	base, _ := url.Parse("https://app.test/dir/")
	if got := resolve(base, "../up"); got != "https://app.test/up" {
		t.Errorf("resolve relative = %q", got)
	}
	if got := resolve(base, "javascript:alert(1)"); got != "" {
		t.Errorf("javascript: should be dropped, got %q", got)
	}
	if got := resolve(base, "page#frag"); got != "https://app.test/dir/page" {
		t.Errorf("fragment should be stripped, got %q", got)
	}

	seed, _ := url.Parse("https://app.test/")
	if inScope("https://evil.test/x", seed, Options{SameHostOnly: true}) {
		t.Error("off-host should be out of scope")
	}
	if !inScope("https://app.test/y", seed, Options{SameHostOnly: true}) {
		t.Error("same-host should be in scope")
	}
}

func TestCrawlInvalidSeed(t *testing.T) {
	if _, err := crawlWith(context.Background(), "not-a-url", Options{}, fakeVisit(nil)); err == nil {
		t.Error("expected error for invalid seed")
	}
}
