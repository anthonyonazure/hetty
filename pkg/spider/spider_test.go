package spider_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/dstotijn/hetty/pkg/spider"
)

func linkedSite() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/a">a</a> <a href="/b">b</a> <a href="https://external.example/x">ext</a></body></html>`)
	})
	mux.HandleFunc("/a", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body><a href="/c">c</a> <a href="/a">self</a></body></html>`)
	})
	mux.HandleFunc("/b", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>leaf b</body></html>`)
	})
	mux.HandleFunc("/c", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><body>leaf c</body></html>`)
	})
	return httptest.NewServer(mux)
}

func has(urls []string, suffix string) bool {
	for _, u := range urls {
		if strings.HasSuffix(u, suffix) {
			return true
		}
	}
	return false
}

func TestCrawlDiscoversInScope(t *testing.T) {
	srv := linkedSite()
	defer srv.Close()

	opts := spider.DefaultOptions()
	opts.MaxDepth = 3
	opts.SameHostOnly = true

	res, err := spider.New().Crawl(context.Background(), srv.URL+"/", opts)
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}

	for _, p := range []string{"/a", "/b", "/c"} {
		if !has(res.URLs, p) {
			t.Errorf("expected to discover %s; got %v", p, res.URLs)
		}
	}
	for _, u := range res.URLs {
		if strings.Contains(u, "external.example") {
			t.Errorf("external host should be out of scope: %s", u)
		}
	}
}

func TestCrawlRespectsMaxPages(t *testing.T) {
	srv := linkedSite()
	defer srv.Close()

	opts := spider.DefaultOptions()
	opts.MaxDepth = 5
	opts.MaxPages = 2

	res, err := spider.New().Crawl(context.Background(), srv.URL+"/", opts)
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if len(res.Pages) > 2 {
		t.Errorf("crawled %d pages, want <= 2", len(res.Pages))
	}
}

func TestCrawlDepthLimit(t *testing.T) {
	srv := linkedSite()
	defer srv.Close()

	opts := spider.DefaultOptions()
	opts.MaxDepth = 0 // only the seed

	res, err := spider.New().Crawl(context.Background(), srv.URL+"/", opts)
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if len(res.Pages) != 1 {
		t.Errorf("depth 0 crawled %d pages, want 1", len(res.Pages))
	}
}
