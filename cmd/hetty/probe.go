package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/dstotijn/hetty/pkg/asm"
	"github.com/dstotijn/hetty/pkg/assetgraph"
	"github.com/dstotijn/hetty/pkg/exttool"
	"github.com/dstotijn/hetty/pkg/monitor"
	"github.com/dstotijn/hetty/pkg/portscan"
	"github.com/dstotijn/hetty/pkg/recon"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/screenshot"
	"github.com/dstotijn/hetty/pkg/template"
	"github.com/dstotijn/hetty/pkg/tlsscan"
	"github.com/dstotijn/hetty/pkg/wafdetect"
	"github.com/dstotijn/hetty/pkg/workflow"
)

// asmRunner is the subset of *asm.Engine the prober needs (avoids an import
// cycle in field ordering; *asm.Engine satisfies it).
type asmRunner interface {
	Run(ctx context.Context, ws *asm.Workspace, mode asm.Mode, opts asm.RunOptions) asm.RunSummary
}

// platform bundles the engines so the monitor prober and workflow step-runner
// can drive them.
type platform struct {
	recon     *recon.Engine
	scan      *scan.Service
	tmpl      *template.Engine
	templates []*template.Template
	exttools  *exttool.Runner
	graph     *assetgraph.Graph
	workflows *workflow.Store
	asm       asmRunner
}

func nowTS() string { return time.Now().UTC().Format(time.RFC3339) }

// probe runs a monitor schedule's check and returns the normalized item set used
// for diffing. Kinds: subdomains, portscan, fingerprint, tlsscan, wafdetect, and
// tool:<name>.
func (p *platform) probe(s monitor.Schedule) ([]string, error) {
	ctx := context.Background()
	host := bareHost(s.Target)
	url := ensureURL(s.Target)

	now := nowTS()
	switch {
	case s.Kind == "subdomains":
		res, err := p.recon.EnumerateSubdomains(ctx, host, recon.Options{Concurrency: 20})
		if err != nil {
			return nil, err
		}
		var items []string
		for _, sd := range res.Subdomains {
			items = append(items, sd.Host)
			if p.graph != nil {
				p.graph.IngestSubdomain(host, sd.Host, "monitor", now)
			}
		}
		return dedup(items), nil

	case s.Kind == "portscan":
		res, err := portscan.Scan(ctx, host, portscan.Options{TopPorts: 100})
		if err != nil {
			return nil, err
		}
		var items []string
		for _, pt := range res.Open {
			items = append(items, fmt.Sprintf("port:%d/%s", pt.Port, pt.Service))
			if p.graph != nil {
				p.graph.IngestService(host, pt.Port, pt.Service, pt.Banner, "monitor", now)
			}
		}
		return dedup(items), nil

	case s.Kind == "fingerprint":
		t, err := p.recon.Fingerprint(ctx, url)
		if err != nil {
			return nil, err
		}
		if p.graph != nil {
			p.graph.IngestURL(host, url, t.Technologies, "monitor", now)
		}
		return dedup(prefixed("tech:", t.Technologies)), nil

	case s.Kind == "tlsscan":
		r, err := tlsscan.Scan(ctx, host, tlsscan.Options{})
		if err != nil {
			return nil, err
		}
		items := prefixed("proto:", r.Protocols)
		items = append(items, prefixed("issue:", r.Issues)...)
		return dedup(items), nil

	case s.Kind == "wafdetect":
		r, err := wafdetect.Detect(ctx, asmHTTPClient, url)
		if err != nil {
			return nil, err
		}
		var items []string
		for _, d := range r.Detected {
			items = append(items, "waf:"+d.Name)
		}
		return dedup(items), nil

	case strings.HasPrefix(s.Kind, "tool:"):
		name := strings.TrimPrefix(s.Kind, "tool:")
		out, err := p.exttools.RunSync(ctx, name, s.Target, s.Extra)
		if err != nil && out == "" {
			return nil, err
		}
		return outputLines(out), nil

	case strings.HasPrefix(s.Kind, "workflow:"):
		if p.workflows == nil {
			return nil, fmt.Errorf("monitor: workflows unavailable")
		}
		wf, ok := p.workflows.Get(strings.TrimPrefix(s.Kind, "workflow:"))
		if !ok {
			return nil, fmt.Errorf("monitor: unknown workflow %q", s.Kind)
		}
		var items []string
		for _, step := range wf.Steps {
			out, _ := p.workflowStep(ctx, s.Target, step)
			items = append(items, outputLines(out)...)
		}
		return dedup(items), nil

	case strings.HasPrefix(s.Kind, "asm:"):
		if p.asm == nil {
			return nil, fmt.Errorf("monitor: attack-surface engine unavailable")
		}
		ws := &asm.Workspace{Name: "monitor", Targets: []string{s.Target}}
		p.asm.Run(ctx, ws, asm.Mode(strings.TrimPrefix(s.Kind, "asm:")), asm.RunOptions{})
		var items []string
		for _, h := range ws.Hosts {
			if p.graph != nil {
				p.graph.IngestHost(h.Host, "monitor", now)
			}
			for _, pt := range h.Ports {
				items = append(items, fmt.Sprintf("%s:port:%d", h.Host, pt.Port))
				if p.graph != nil {
					p.graph.IngestService(h.Host, pt.Port, pt.Service, pt.Banner, "monitor", now)
				}
			}
			for _, f := range h.Findings {
				items = append(items, h.Host+":finding:"+f.Title)
				if p.graph != nil {
					p.graph.IngestFinding(h.Host, f.Title, f.Severity, "monitor", now)
				}
			}
		}
		return dedup(items), nil

	default:
		return nil, fmt.Errorf("monitor: unsupported kind %q", s.Kind)
	}
}

// workflowStep runs one workflow step and returns its text output.
func (p *platform) workflowStep(ctx context.Context, target string, step workflow.Step) (string, error) {
	host := bareHost(target)
	url := ensureURL(target)

	if step.Type == "tool" {
		return p.exttools.RunSync(ctx, step.Name, target, step.Extra)
	}

	now := nowTS()
	// native steps
	switch step.Name {
	case "subdomains":
		res, err := p.recon.EnumerateSubdomains(ctx, host, recon.Options{Concurrency: 20})
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, sd := range res.Subdomains {
			fmt.Fprintf(&b, "%s\n", sd.Host)
			if p.graph != nil {
				p.graph.IngestSubdomain(host, sd.Host, "workflow", now)
			}
		}
		return b.String(), nil
	case "portscan":
		res, err := portscan.Scan(ctx, host, portscan.Options{TopPorts: 100, Banner: true})
		if err != nil {
			return "", err
		}
		var b strings.Builder
		for _, pt := range res.Open {
			fmt.Fprintf(&b, "%d/%s %s\n", pt.Port, pt.Service, pt.Banner)
			if p.graph != nil {
				p.graph.IngestService(host, pt.Port, pt.Service, pt.Banner, "workflow", now)
			}
		}
		return b.String(), nil
	case "fingerprint":
		t, err := p.recon.Fingerprint(ctx, url)
		if err != nil {
			return "", err
		}
		if p.graph != nil {
			p.graph.IngestURL(host, url, t.Technologies, "workflow", now)
		}
		return fmt.Sprintf("%s — server=%s tech=%s", t.Title, t.Server, strings.Join(t.Technologies, ", ")), nil
	case "tlsscan":
		r, err := tlsscan.Scan(ctx, host, tlsscan.Options{})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("protocols=%s issues=%s", strings.Join(r.Protocols, ","), strings.Join(r.Issues, "; ")), nil
	case "wafdetect":
		r, err := wafdetect.Detect(ctx, asmHTTPClient, url)
		if err != nil {
			return "", err
		}
		var names []string
		for _, d := range r.Detected {
			names = append(names, d.Name)
		}
		return "WAF: " + strings.Join(names, ", "), nil
	case "screenshot":
		r, err := screenshot.Capture(ctx, url, screenshot.Options{})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("captured screenshot (%d bytes)", r.Bytes), nil
	case "webscan":
		return p.webscanText(ctx, url), nil
	default:
		return "", fmt.Errorf("workflow: unknown native step %q", step.Name)
	}
}

func (p *platform) webscanText(ctx context.Context, url string) string {
	var b strings.Builder
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		if res, err := asmHTTPClient.Do(req); err == nil {
			rt, _ := scan.RequestTemplateFromHTTP(res.Request)
			sresp, _ := scan.ResponseFromHTTP(res)
			res.Body.Close()
			if rt != nil && sresp != nil {
				for _, pc := range p.scan.Registry().PassiveChecks() {
					for _, f := range pc.Check(rt, sresp) {
						fmt.Fprintf(&b, "[%s] %s\n", f.Severity, f.Name)
					}
				}
			}
		}
	}
	if p.tmpl != nil {
		if matches, err := p.tmpl.Run(ctx, url, p.templates, template.Options{TimeoutMs: 8000}); err == nil {
			for _, m := range matches {
				fmt.Fprintf(&b, "[%s] template %s\n", m.Severity, m.Name)
			}
		}
	}
	if b.Len() == 0 {
		return "no passive/template findings"
	}
	return b.String()
}

// sendAlert posts a change notification to a webhook (Slack-compatible {"text"}).
func sendAlert(s monitor.Schedule, d monitor.Diff) {
	var msg strings.Builder
	fmt.Fprintf(&msg, "🛰️ hetty monitor — %s (%s)\n", s.Name, s.Target)
	if len(d.Added) > 0 {
		fmt.Fprintf(&msg, "NEW (+%d): %s\n", len(d.Added), strings.Join(cap20(d.Added), ", "))
	}
	if len(d.Removed) > 0 {
		fmt.Fprintf(&msg, "GONE (-%d): %s\n", len(d.Removed), strings.Join(cap20(d.Removed), ", "))
	}
	body, _ := json.Marshal(map[string]string{"text": msg.String()})
	req, err := http.NewRequest(http.MethodPost, s.AlertURL, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if resp, err := asmHTTPClient.Do(req); err == nil {
		resp.Body.Close()
	}
}

// --- helpers ---------------------------------------------------------------

func dedup(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out
}

func prefixed(prefix string, in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		out = append(out, prefix+s)
	}
	return out
}

func outputLines(out string) []string {
	var items []string
	for _, line := range strings.Split(out, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			items = append(items, l)
		}
	}
	return dedup(items)
}

func cap20(in []string) []string {
	if len(in) > 20 {
		return append(in[:20:20], fmt.Sprintf("…+%d more", len(in)-20))
	}
	return in
}

// bareHost reduces a URL or host:port to the bare host.
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

// ensureURL prepends https:// when no scheme is present.
func ensureURL(s string) string {
	if strings.Contains(s, "://") {
		return s
	}
	return "https://" + s
}
