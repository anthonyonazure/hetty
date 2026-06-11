// Package wafdetect fingerprints Web Application Firewalls (wafw00f-style) by
// sending a benign request and a malicious probe and matching the responses
// against a signature database of headers, cookies, and body markers.
package wafdetect

import (
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Detection is a single matched WAF.
type Detection struct {
	Name       string `json:"name"`
	Confidence string `json:"confidence"` // firm | tentative
	Evidence   string `json:"evidence"`
}

// Result is the outcome of WAF detection.
type Result struct {
	URL            string      `json:"url"`
	Detected       []Detection `json:"detected"`
	Blocked        bool        `json:"blocked"`
	BaselineStatus int         `json:"baselineStatus"`
	ProbeStatus    int         `json:"probeStatus"`
}

// the probe carries payloads that commonly trip a WAF.
const probePayload = `../../../../etc/passwd' OR '1'='1 <script>alert(1)</script>`

// Detect probes target and reports any WAFs fingerprinted. client may be nil.
func Detect(ctx context.Context, client *http.Client, target string) (Result, error) {
	if client == nil {
		client = http.DefaultClient
	}

	res := Result{URL: target}

	baseline, bBody, err := fetch(ctx, client, target)
	if err != nil {
		return res, err
	}
	if baseline != nil {
		res.BaselineStatus = baseline.StatusCode
	}

	probeURL := appendProbe(target)
	probe, pBody, _ := fetch(ctx, client, probeURL)
	if probe != nil {
		res.ProbeStatus = probe.StatusCode
	}

	seen := map[string]bool{}
	for _, resp := range []*responseData{
		{resp: baseline, body: bBody},
		{resp: probe, body: pBody},
	} {
		if resp.resp == nil {
			continue
		}
		for _, d := range match(resp.resp, resp.body) {
			if !seen[d.Name] {
				seen[d.Name] = true
				res.Detected = append(res.Detected, d)
			}
		}
	}

	// Behavioral blocking: the malicious probe was rejected differently.
	if probe != nil && baseline != nil {
		blockStatus := probe.StatusCode == http.StatusForbidden ||
			probe.StatusCode == http.StatusNotAcceptable ||
			probe.StatusCode == http.StatusTooManyRequests ||
			probe.StatusCode == 501 || probe.StatusCode == 999
		if blockStatus && probe.StatusCode != baseline.StatusCode {
			res.Blocked = true
		}
	}

	return res, nil
}

type responseData struct {
	resp *http.Response
	body string
}

func fetch(ctx context.Context, client *http.Client, target string) (*http.Response, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; HettyWAFDetect/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256<<10))
	return resp, string(body), nil
}

func appendProbe(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return target
	}
	q := u.Query()
	q.Set("wafprobe", probePayload)
	u.RawQuery = q.Encode()
	return u.String()
}

// match runs the signature DB against a response.
func match(resp *http.Response, body string) []Detection {
	var out []Detection
	lowerBody := strings.ToLower(body)
	server := strings.ToLower(resp.Header.Get("Server"))

	for _, sig := range signatures {
		// Header presence/value.
		for h, want := range sig.headers {
			val := resp.Header.Get(h)
			if val == "" {
				continue
			}
			if want == "" || strings.Contains(strings.ToLower(val), want) {
				out = append(out, Detection{Name: sig.name, Confidence: "firm", Evidence: "header " + h + ": " + val})
				goto next
			}
		}
		// Server banner.
		if sig.server != "" && strings.Contains(server, sig.server) {
			out = append(out, Detection{Name: sig.name, Confidence: "firm", Evidence: "Server: " + resp.Header.Get("Server")})
			goto next
		}
		// Cookies.
		for _, c := range resp.Cookies() {
			for _, ck := range sig.cookies {
				if strings.Contains(strings.ToLower(c.Name), ck) {
					out = append(out, Detection{Name: sig.name, Confidence: "firm", Evidence: "cookie " + c.Name})
					goto next
				}
			}
		}
		// Body markers.
		for _, m := range sig.body {
			if strings.Contains(lowerBody, m) {
				out = append(out, Detection{Name: sig.name, Confidence: "tentative", Evidence: "body marker: " + m})
				goto next
			}
		}
	next:
	}
	return out
}
