package asm

import (
	"context"
	"fmt"
	"net"
	"strings"
)

// Mode selects how much of the pipeline a sweep runs (Sn1per-style scan modes).
type Mode string

const (
	// ModeRecon: subdomains, port scan, TLS, fingerprint, WAF, vuln-match.
	ModeRecon Mode = "recon"
	// ModeWeb: fingerprint, WAF, web vulnerability scan, screenshot.
	ModeWeb Mode = "web"
	// ModeFull: recon + web.
	ModeFull Mode = "full"
	// ModeNuke: full + auto-exploitation of matched vulns via Metasploit.
	ModeNuke Mode = "nuke"
)

// Toolbox holds the engine callbacks the orchestrator drives. Any nil hook is
// skipped, which keeps pkg/asm decoupled from the concrete engine packages and
// trivially testable with fakes.
type Toolbox struct {
	Subdomains  func(ctx context.Context, domain string) ([]string, error)
	Fingerprint func(ctx context.Context, url string) (Tech, error)
	PortScan    func(ctx context.Context, host string, full bool) ([]Port, error)
	TLSScan     func(ctx context.Context, host string) (*TLSSummary, error)
	WAFDetect   func(ctx context.Context, url string) ([]string, error)
	WebScan     func(ctx context.Context, url string) ([]Finding, error)
	Screenshot  func(ctx context.Context, url string) (string, error)
	VulnMatch   func(banner string) []Vuln
	Exploit     func(ctx context.Context, module string, opts map[string]interface{}) (string, error)
}

// RunOptions tunes a sweep.
type RunOptions struct {
	FullPortScan bool `json:"fullPortScan"`
	Screenshot   bool `json:"screenshot"`
	AllowExploit bool `json:"allowExploit"` // required gate for ModeNuke exploitation
}

// RunSummary reports what a sweep did.
type RunSummary struct {
	Mode         Mode     `json:"mode"`
	HostsScanned int      `json:"hostsScanned"`
	OpenPorts    int      `json:"openPorts"`
	Findings     int      `json:"findings"`
	Exploited    int      `json:"exploited"`
	Errors       []string `json:"errors,omitempty"`
}

func (s *RunSummary) errf(format string, a ...interface{}) {
	s.Errors = append(s.Errors, fmt.Sprintf(format, a...))
}

// Engine orchestrates sweeps.
type Engine struct {
	tb Toolbox
}

// New returns an orchestrator bound to the given toolbox.
func New(tb Toolbox) *Engine { return &Engine{tb: tb} }

// Run executes mode against every target in ws, populating ws in place.
func (e *Engine) Run(ctx context.Context, ws *Workspace, mode Mode, opts RunOptions) RunSummary {
	sum := RunSummary{Mode: mode}

	recon := mode == ModeRecon || mode == ModeFull || mode == ModeNuke
	web := mode == ModeWeb || mode == ModeFull || mode == ModeNuke

	for _, target := range ws.Targets {
		if ctx.Err() != nil {
			sum.errf("aborted: %v", ctx.Err())
			break
		}
		host := bareHost(target)
		url := ensureURL(target)
		h := ws.host(host)
		sum.HostsScanned++

		if recon {
			e.recon(ctx, ws, h, host, url, opts, &sum)
		}
		if web {
			e.web(ctx, h, url, opts, &sum)
		}
		if mode == ModeNuke {
			e.nuke(ctx, h, host, opts, &sum)
		}
	}

	ws.LastMode = string(mode)
	return sum
}

func (e *Engine) recon(ctx context.Context, ws *Workspace, h *Host, host, url string, opts RunOptions, sum *RunSummary) {
	if e.tb.Subdomains != nil && isDomain(host) {
		if subs, err := e.tb.Subdomains(ctx, host); err != nil {
			sum.errf("%s subdomains: %v", host, err)
		} else {
			ws.Subdomains = mergeUnique(ws.Subdomains, subs)
		}
	}

	if e.tb.PortScan != nil {
		ports, err := e.tb.PortScan(ctx, host, opts.FullPortScan)
		if err != nil {
			sum.errf("%s portscan: %v", host, err)
		} else {
			h.Ports = ports
			sum.OpenPorts += len(ports)
			if e.tb.VulnMatch != nil {
				for i := range h.Ports {
					if h.Ports[i].Banner != "" {
						h.Ports[i].Vulns = e.tb.VulnMatch(h.Ports[i].Banner)
					}
				}
			}
		}
	}

	if e.tb.TLSScan != nil {
		if t, err := e.tb.TLSScan(ctx, host); err != nil {
			// TLS failures are common (no TLS service) — record quietly.
			_ = err
		} else {
			h.TLS = t
		}
	}

	e.fingerprint(ctx, h, url, sum, host)

	if e.tb.WAFDetect != nil {
		if waf, err := e.tb.WAFDetect(ctx, url); err == nil {
			h.WAF = waf
		}
	}
}

func (e *Engine) web(ctx context.Context, h *Host, url string, opts RunOptions, sum *RunSummary) {
	e.fingerprint(ctx, h, url, sum, h.Host)

	if e.tb.WebScan != nil {
		if f, err := e.tb.WebScan(ctx, url); err != nil {
			sum.errf("%s webscan: %v", h.Host, err)
		} else {
			h.Findings = append(h.Findings, f...)
			sum.Findings += len(f)
		}
	}

	if opts.Screenshot && e.tb.Screenshot != nil {
		if img, err := e.tb.Screenshot(ctx, url); err == nil {
			h.Screenshot = img
		}
	}
}

func (e *Engine) fingerprint(ctx context.Context, h *Host, url string, sum *RunSummary, host string) {
	if h.Tech != nil || e.tb.Fingerprint == nil {
		return
	}
	if t, err := e.tb.Fingerprint(ctx, url); err != nil {
		sum.errf("%s fingerprint: %v", host, err)
	} else {
		h.Tech = &t
	}
}

func (e *Engine) nuke(ctx context.Context, h *Host, host string, opts RunOptions, sum *RunSummary) {
	if !opts.AllowExploit || e.tb.Exploit == nil {
		return
	}
	for _, p := range h.Ports {
		for _, v := range p.Vulns {
			if !v.ExploitAvailable || v.MSFModule == "" {
				continue
			}
			status, detail := "attempted", ""
			res, err := e.tb.Exploit(ctx, v.MSFModule, map[string]interface{}{
				"RHOSTS": host,
				"RPORT":  int64(p.Port),
			})
			if err != nil {
				status, detail = "failed", err.Error()
			} else {
				detail = res
			}
			h.Exploits = append(h.Exploits, ExploitResult{
				Module: v.MSFModule, Target: host, Status: status, Detail: detail,
			})
			sum.Exploited++
		}
	}
}

// --- helpers ---------------------------------------------------------------

func bareHost(s string) string {
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if h, _, err := net.SplitHostPort(s); err == nil {
		return h
	}
	return s
}

func ensureURL(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "https://" + s
}

func isDomain(host string) bool {
	if net.ParseIP(host) != nil {
		return false
	}
	return strings.Contains(host, ".")
}

func mergeUnique(existing, add []string) []string {
	seen := map[string]bool{}
	for _, e := range existing {
		seen[e] = true
	}
	for _, a := range add {
		if !seen[a] {
			seen[a] = true
			existing = append(existing, a)
		}
	}
	return existing
}
