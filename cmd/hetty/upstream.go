package main

import (
	"crypto/tls"
	"net"
	"net/http"
	neturl "net/url"
	"time"
)

// proxyTransport builds an http.Transport that routes through the given
// upstream proxy. http.Transport natively supports http://, https:// and
// socks5:// proxy URLs, so a single code path covers all three.
func proxyTransport(u *neturl.URL) *http.Transport {
	return &http.Transport{
		Proxy:               http.ProxyURL(u),
		DialContext:         (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:        100,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		//nolint:gosec
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
}

// proxyHTTPClient builds an http.Client routed through the upstream proxy.
// followRedirects=false preserves accurate status codes (used by the scanner).
func proxyHTTPClient(u *neturl.URL, timeout time.Duration, followRedirects bool) *http.Client {
	c := &http.Client{Transport: proxyTransport(u), Timeout: timeout}
	if !followRedirects {
		c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}
