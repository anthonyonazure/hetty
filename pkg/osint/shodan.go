// Package osint provides open-source-intelligence lookups for the
// attack-surface scanner. Currently it wraps the Shodan host API (key-gated).
package osint

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// Client is a Shodan API client.
type Client struct {
	apiKey  string
	baseURL string
	http    *http.Client
}

// New returns a Shodan client. An empty apiKey leaves it disabled.
func New(apiKey string) *Client {
	return &Client{
		apiKey:  apiKey,
		baseURL: "https://api.shodan.io",
		http:    &http.Client{Timeout: 15 * time.Second},
	}
}

// Enabled reports whether an API key is configured.
func (c *Client) Enabled() bool { return c != nil && c.apiKey != "" }

// SetBaseURL overrides the API base URL (used in tests).
func (c *Client) SetBaseURL(u string) { c.baseURL = u }

// Service is one banner observed on a host.
type Service struct {
	Port      int    `json:"port"`
	Transport string `json:"transport"`
	Product   string `json:"product"`
	Version   string `json:"version"`
}

// Host is the OSINT summary for an IP.
type Host struct {
	IP        string    `json:"ip"`
	Org       string    `json:"org"`
	OS        string    `json:"os"`
	Hostnames []string  `json:"hostnames"`
	Ports     []int     `json:"ports"`
	Vulns     []string  `json:"vulns"`
	Services  []Service `json:"services"`
}

// Host looks up an IP via Shodan's host endpoint.
func (c *Client) Host(ctx context.Context, ip string) (Host, error) {
	if !c.Enabled() {
		return Host{}, fmt.Errorf("osint: Shodan API key not configured")
	}

	endpoint := fmt.Sprintf("%s/shodan/host/%s?key=%s", c.baseURL, url.PathEscape(ip), url.QueryEscape(c.apiKey))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Host{}, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return Host{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))

	if resp.StatusCode != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		if e.Error != "" {
			return Host{}, fmt.Errorf("osint: shodan: %s", e.Error)
		}
		return Host{}, fmt.Errorf("osint: shodan returned %s", resp.Status)
	}

	var raw struct {
		IPStr     string   `json:"ip_str"`
		Org       string   `json:"org"`
		OS        string   `json:"os"`
		Hostnames []string `json:"hostnames"`
		Ports     []int    `json:"ports"`
		Vulns     []string `json:"vulns"`
		Data      []struct {
			Port      int    `json:"port"`
			Transport string `json:"transport"`
			Product   string `json:"product"`
			Version   string `json:"version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return Host{}, fmt.Errorf("osint: decode shodan response: %w", err)
	}

	host := Host{
		IP:        raw.IPStr,
		Org:       raw.Org,
		OS:        raw.OS,
		Hostnames: raw.Hostnames,
		Ports:     raw.Ports,
		Vulns:     raw.Vulns,
	}
	if host.IP == "" {
		host.IP = ip
	}
	for _, d := range raw.Data {
		host.Services = append(host.Services, Service{
			Port: d.Port, Transport: d.Transport, Product: d.Product, Version: d.Version,
		})
	}
	return host, nil
}
