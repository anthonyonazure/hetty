// Package recon performs passive attack-surface discovery — Hetty's lightweight
// take on the recon workflow of amass / bbot / reconftw. It enumerates a
// domain's subdomains from Certificate Transparency logs (crt.sh), resolves
// which are live via DNS, and fingerprints a host's technology stack
// (WhatWeb-style) from response headers, cookies and body signatures.
package recon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dstotijn/hetty/pkg/ratelimit"
)

// Subdomain is a discovered host.
type Subdomain struct {
	Host      string   `json:"host"`
	Resolved  bool     `json:"resolved"`
	Addresses []string `json:"addresses,omitempty"`
}

// Result is the output of subdomain enumeration.
type Result struct {
	Domain     string      `json:"domain"`
	Subdomains []Subdomain `json:"subdomains"`
	Sources    []string    `json:"sources"`
	Total      int         `json:"total"`
	Resolved   int         `json:"resolved"`
}

// Engine performs recon. Its HTTP and DNS dependencies are injectable for tests.
type Engine struct {
	httpClient *http.Client
	crtshBase  string
	lookupHost func(ctx context.Context, host string) ([]string, error)
}

// New returns a recon engine.
func New() *Engine {
	return &Engine{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
			//nolint:gosec
			Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		},
		crtshBase: "https://crt.sh",
		lookupHost: func(ctx context.Context, host string) ([]string, error) {
			return net.DefaultResolver.LookupHost(ctx, host)
		},
	}
}

// Options configures enumeration.
type Options struct {
	Resolve     bool    `json:"resolve"`     // resolve discovered hosts via DNS
	Concurrency int     `json:"concurrency"` // DNS resolution concurrency
	RequestsPerSecond float64 `json:"requestsPerSecond"`
}

type crtshEntry struct {
	NameValue string `json:"name_value"`
}

// EnumerateSubdomains discovers subdomains of domain from crt.sh and optionally
// resolves them.
func (e *Engine) EnumerateSubdomains(ctx context.Context, domain string, opts Options) (Result, error) {
	domain = strings.TrimSpace(strings.ToLower(domain))
	if domain == "" || strings.Contains(domain, "/") {
		return Result{}, fmt.Errorf("recon: domain must be a bare hostname (e.g. example.com)")
	}

	names, err := e.queryCrtsh(ctx, domain)
	if err != nil {
		return Result{}, err
	}

	result := Result{Domain: domain, Sources: []string{"crt.sh"}}
	if !opts.Resolve {
		for _, n := range names {
			result.Subdomains = append(result.Subdomains, Subdomain{Host: n})
		}
		result.Total = len(names)
		return result, nil
	}

	limiter := ratelimit.New(ratelimit.Config{
		RequestsPerSecond: opts.RequestsPerSecond,
		MaxConcurrent:     orDefault(opts.Concurrency, 20),
	})

	subs := make([]Subdomain, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		i, n := i, n
		wg.Add(1)
		go func() {
			defer wg.Done()
			s := Subdomain{Host: n}
			if release, err := limiter.Acquire(ctx); err == nil {
				addrs, err := e.lookupHost(ctx, n)
				release()
				if err == nil && len(addrs) > 0 {
					s.Resolved = true
					s.Addresses = dedupeSorted(addrs)
				}
			}
			subs[i] = s
		}()
	}
	wg.Wait()

	resolved := 0
	for _, s := range subs {
		if s.Resolved {
			resolved++
		}
	}
	result.Subdomains = subs
	result.Total = len(subs)
	result.Resolved = resolved
	return result, nil
}

func (e *Engine) queryCrtsh(ctx context.Context, domain string) ([]string, error) {
	u := fmt.Sprintf("%s/?q=%s&output=json", e.crtshBase, url.QueryEscape("%."+domain))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hetty-recon")

	res, err := e.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("recon: crt.sh query failed: %w", err)
	}
	defer res.Body.Close()

	body, err := io.ReadAll(io.LimitReader(res.Body, 32<<20))
	if err != nil {
		return nil, err
	}

	var entries []crtshEntry
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("recon: crt.sh returned unexpected data")
	}

	set := map[string]struct{}{}
	for _, e := range entries {
		for _, raw := range strings.Split(e.NameValue, "\n") {
			name := strings.TrimSpace(strings.ToLower(raw))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || strings.ContainsAny(name, " @*") {
				continue
			}
			if name == domain || strings.HasSuffix(name, "."+domain) {
				set[name] = struct{}{}
			}
		}
	}

	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out, nil
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

func dedupeSorted(in []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}
