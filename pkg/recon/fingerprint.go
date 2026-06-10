package recon

import (
	"context"
	"io"
	"net/http"
	"sort"
	"strings"
)

// Tech is a host's detected technology stack.
type Tech struct {
	URL          string   `json:"url"`
	Status       int      `json:"status"`
	Server       string   `json:"server,omitempty"`
	Powered      string   `json:"poweredBy,omitempty"`
	Title        string   `json:"title,omitempty"`
	Technologies []string `json:"technologies"`
}

type signature struct {
	tech   string
	header string // header to inspect (empty = body)
	needle string // case-insensitive substring; or regex-free contains
}

// signatures is a compact WhatWeb-style fingerprint set: a substring in a
// header, cookie, or the response body implies a technology.
var signatures = []signature{
	{"WordPress", "", "/wp-content/"},
	{"WordPress", "", "wp-includes"},
	{"Drupal", "", "Drupal.settings"},
	{"Drupal", "x-generator", "drupal"},
	{"Joomla", "", "/media/jui/"},
	{"Joomla", "", "com_content"},
	{"Magento", "", "Mage.Cookies"},
	{"Shopify", "", "cdn.shopify.com"},
	{"Next.js", "", "__NEXT_DATA__"},
	{"Nuxt.js", "", "__NUXT__"},
	{"React", "", "data-reactroot"},
	{"Angular", "", "ng-version"},
	{"Vue.js", "", "data-v-app"},
	{"Laravel", "set-cookie", "laravel_session"},
	{"Laravel", "set-cookie", "xsrf-token"},
	{"Django", "", "csrfmiddlewaretoken"},
	{"Django", "set-cookie", "django"},
	{"Flask", "set-cookie", "session="},
	{"Rails", "set-cookie", "_rails"},
	{"PHP", "set-cookie", "phpsessid"},
	{"Java", "set-cookie", "jsessionid"},
	{"ASP.NET", "set-cookie", "asp.net_sessionid"},
	{"ASP.NET", "", "__VIEWSTATE"},
	{"Express", "x-powered-by", "express"},
	{"jQuery", "", "jquery"},
	{"Bootstrap", "", "bootstrap"},
	{"Cloudflare", "server", "cloudflare"},
	{"nginx", "server", "nginx"},
	{"Apache", "server", "apache"},
	{"IIS", "server", "iis"},
	{"OpenResty", "server", "openresty"},
	{"GraphQL", "", "__schema"},
	{"Swagger", "", "swagger-ui"},
	{"WAF: Cloudflare", "", "Attention Required! | Cloudflare"},
	{"Akamai", "server", "akamaighost"},
}

// Fingerprint fetches url and detects its technology stack.
func (e *Engine) Fingerprint(ctx context.Context, url string) (Tech, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Tech{}, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (hetty-recon)")

	res, err := e.httpClient.Do(req)
	if err != nil {
		return Tech{}, err
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, 2<<20))

	t := Tech{
		URL:     url,
		Status:  res.StatusCode,
		Server:  res.Header.Get("Server"),
		Powered: res.Header.Get("X-Powered-By"),
		Title:   extractTitle(body),
	}

	bodyLower := strings.ToLower(string(body))
	set := map[string]struct{}{}

	for _, sig := range signatures {
		if sig.needle == "" {
			continue
		}
		needle := strings.ToLower(sig.needle)
		var hay string
		if sig.header == "" {
			hay = bodyLower
		} else {
			hay = strings.ToLower(headerValues(res.Header, sig.header))
		}
		if strings.Contains(hay, needle) {
			set[sig.tech] = struct{}{}
		}
	}
	if t.Powered != "" {
		set[t.Powered] = struct{}{}
	}

	techs := make([]string, 0, len(set))
	for tech := range set {
		techs = append(techs, tech)
	}
	sort.Strings(techs)
	t.Technologies = techs
	return t, nil
}

func headerValues(h http.Header, name string) string {
	// Set-Cookie is multi-valued; join all values.
	canonical := http.CanonicalHeaderKey(name)
	return strings.Join(h.Values(canonical), "; ")
}

func extractTitle(body []byte) string {
	s := strings.ToLower(string(body))
	i := strings.Index(s, "<title")
	if i < 0 {
		return ""
	}
	gt := strings.IndexByte(s[i:], '>')
	if gt < 0 {
		return ""
	}
	start := i + gt + 1
	end := strings.Index(s[start:], "</title>")
	if end < 0 {
		return ""
	}
	title := string(body[start : start+end])
	title = strings.TrimSpace(title)
	if len(title) > 200 {
		title = title[:200]
	}
	return title
}
