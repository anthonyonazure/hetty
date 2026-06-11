package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/dstotijn/hetty/pkg/asm"
	"github.com/dstotijn/hetty/pkg/msf"
	"github.com/dstotijn/hetty/pkg/portscan"
	"github.com/dstotijn/hetty/pkg/recon"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/screenshot"
	"github.com/dstotijn/hetty/pkg/template"
	"github.com/dstotijn/hetty/pkg/tlsscan"
	"github.com/dstotijn/hetty/pkg/vulnmatch"
	"github.com/dstotijn/hetty/pkg/wafdetect"
)

// asmHTTPClient is a permissive client for ASM probes (ignores TLS errors,
// doesn't follow redirects so status codes stay accurate).
var asmHTTPClient = &http.Client{
	Timeout: 20 * time.Second,
	//nolint:gosec
	Transport:     &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// newASMToolbox binds the ASM orchestrator's hooks to the concrete engines.
func newASMToolbox(
	reconEngine *recon.Engine,
	scanService *scan.Service,
	tmplEngine *template.Engine,
	templates []*template.Template,
	msfClient *msf.Client,
) asm.Toolbox {
	return asm.Toolbox{
		Subdomains: func(ctx context.Context, domain string) ([]string, error) {
			res, err := reconEngine.EnumerateSubdomains(ctx, domain, recon.Options{Concurrency: 20})
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(res.Subdomains))
			for _, s := range res.Subdomains {
				out = append(out, s.Host)
			}
			return out, nil
		},

		Fingerprint: func(ctx context.Context, url string) (asm.Tech, error) {
			t, err := reconEngine.Fingerprint(ctx, url)
			if err != nil {
				return asm.Tech{}, err
			}
			return asm.Tech{Server: t.Server, Powered: t.Powered, Title: t.Title, Technologies: t.Technologies}, nil
		},

		PortScan: func(ctx context.Context, host string, full bool) ([]asm.Port, error) {
			opts := portscan.Options{Banner: true, TopPorts: 100}
			if full {
				ports := make([]int, 0, 1024)
				for p := 1; p <= 1024; p++ {
					ports = append(ports, p)
				}
				opts.Ports = ports
			}
			res, err := portscan.Scan(ctx, host, opts)
			if err != nil {
				return nil, err
			}
			out := make([]asm.Port, 0, len(res.Open))
			for _, p := range res.Open {
				out = append(out, asm.Port{Port: p.Port, Service: p.Service, Banner: p.Banner})
			}
			return out, nil
		},

		TLSScan: func(ctx context.Context, host string) (*asm.TLSSummary, error) {
			r, err := tlsscan.Scan(ctx, host, tlsscan.Options{})
			if err != nil {
				return nil, err
			}
			return &asm.TLSSummary{
				Protocols:       r.Protocols,
				CertSubject:     r.Cert.Subject,
				DaysUntilExpiry: r.Cert.DaysUntilExpiry,
				Issues:          r.Issues,
			}, nil
		},

		WAFDetect: func(ctx context.Context, url string) ([]string, error) {
			r, err := wafdetect.Detect(ctx, asmHTTPClient, url)
			if err != nil {
				return nil, err
			}
			names := make([]string, 0, len(r.Detected))
			for _, d := range r.Detected {
				names = append(names, d.Name)
			}
			return names, nil
		},

		WebScan: func(ctx context.Context, url string) ([]asm.Finding, error) {
			var findings []asm.Finding

			req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
			if err == nil {
				if res, err := asmHTTPClient.Do(req); err == nil {
					rt, _ := scan.RequestTemplateFromHTTP(res.Request)
					sresp, _ := scan.ResponseFromHTTP(res)
					res.Body.Close()
					if rt != nil && sresp != nil {
						for _, pc := range scanService.Registry().PassiveChecks() {
							for _, f := range pc.Check(rt, sresp) {
								findings = append(findings, asm.Finding{
									Source: "passive:" + pc.ID(), Title: f.Name,
									Severity: string(f.Severity), Detail: f.Evidence,
								})
							}
						}
					}
				}
			}

			if tmplEngine != nil {
				if matches, err := tmplEngine.Run(ctx, url, templates, template.Options{TimeoutMs: 8000}); err == nil {
					for _, m := range matches {
						findings = append(findings, asm.Finding{
							Source: "template:" + m.TemplateID, Title: m.Name,
							Severity: m.Severity, Detail: m.MatchedURL,
						})
					}
				}
			}
			return findings, nil
		},

		Screenshot: func(ctx context.Context, url string) (string, error) {
			r, err := screenshot.Capture(ctx, url, screenshot.Options{})
			if err != nil {
				return "", err
			}
			return r.PNGBase64, nil
		},

		VulnMatch: func(banner string) []asm.Vuln {
			matched := vulnmatch.MatchBanner(banner)
			out := make([]asm.Vuln, 0, len(matched))
			for _, v := range matched {
				out = append(out, asm.Vuln{
					CVE: v.CVE, Title: v.Title, Severity: v.Severity,
					ExploitAvailable: v.ExploitAvailable, MSFModule: v.MSFModule,
				})
			}
			return out
		},

		Exploit: func(ctx context.Context, module string, opts map[string]interface{}) (string, error) {
			if msfClient == nil || !msfClient.Enabled() {
				return "", fmt.Errorf("metasploit not configured (set --msf-url)")
			}
			if err := msfClient.EnsureLogin(ctx); err != nil {
				return "", err
			}
			res, err := msfClient.Execute(ctx, module, opts)
			if err != nil {
				return "", err
			}
			if jid, ok := res["job_id"]; ok && jid != nil {
				return fmt.Sprintf("launched job %v", jid), nil
			}
			return "module executed", nil
		},
	}
}
