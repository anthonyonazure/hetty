package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/dstotijn/hetty/pkg/asm"
	"github.com/dstotijn/hetty/pkg/msf"
	"github.com/dstotijn/hetty/pkg/recon"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/template"
)

type sweepCommand struct {
	targets    string
	mode       string
	fullPorts  bool
	exploit    bool
	msfURL     string
	msfUser    string
	msfPass    string
}

// newSweepCommand returns the `hetty sweep` subcommand: a headless Sn1per-style
// attack-surface sweep (recon/web/full/nuke) that prints an aggregated report.
func newSweepCommand() *ffcli.Command {
	c := &sweepCommand{}
	fs := flag.NewFlagSet("hetty sweep", flag.ExitOnError)
	fs.StringVar(&c.targets, "targets", "", "Comma-separated targets (domains/hosts/URLs). Required.")
	fs.StringVar(&c.mode, "mode", "full", "Scan mode: recon | web | full | nuke.")
	fs.BoolVar(&c.fullPorts, "full-ports", false, "Scan ports 1-1024 instead of the top 100.")
	fs.BoolVar(&c.exploit, "exploit", false, "Allow auto-exploitation in nuke mode (requires --msf-url).")
	fs.StringVar(&c.msfURL, "msf-url", "", "Metasploit RPC endpoint (for nuke mode).")
	fs.StringVar(&c.msfUser, "msf-user", "msf", "Metasploit RPC username.")
	fs.StringVar(&c.msfPass, "msf-pass", "", "Metasploit RPC password.")

	return &ffcli.Command{
		Name:       "sweep",
		ShortUsage: "hetty sweep --targets <a,b,c> [--mode full] [flags]",
		ShortHelp:  "Run a headless attack-surface sweep (recon/web/full/nuke) and print a report.",
		FlagSet:    fs,
		Exec:       c.Exec,
	}
}

func (c *sweepCommand) Exec(ctx context.Context, _ []string) error {
	if c.targets == "" {
		return fmt.Errorf("hetty sweep: --targets is required")
	}
	mode := asm.Mode(c.mode)
	switch mode {
	case asm.ModeRecon, asm.ModeWeb, asm.ModeFull, asm.ModeNuke:
	default:
		return fmt.Errorf("hetty sweep: invalid --mode %q (recon|web|full|nuke)", c.mode)
	}

	var targets []string
	for _, t := range strings.Split(c.targets, ",") {
		if t = strings.TrimSpace(t); t != "" {
			targets = append(targets, t)
		}
	}

	scanService := scan.NewService(scan.Config{Repository: newMemScanRepo()})
	tmplEngine := template.New()
	templates := template.Builtins()
	msfClient := msf.New(msf.Config{URL: c.msfURL, User: c.msfUser, Pass: c.msfPass, Insecure: true})

	engine := asm.New(newASMToolbox(recon.New(), scanService, tmplEngine, templates, msfClient))
	ws := &asm.Workspace{Name: "sweep", Targets: targets}

	fmt.Fprintf(os.Stderr, "Sweeping %d target(s) in %s mode...\n", len(targets), mode)
	summary := engine.Run(ctx, ws, mode, asm.RunOptions{
		FullPortScan: c.fullPorts,
		AllowExploit: c.exploit,
	})

	renderSweepReport(os.Stdout, ws, summary)
	return nil
}

func renderSweepReport(w *os.File, ws *asm.Workspace, sum asm.RunSummary) {
	fmt.Fprintf(w, "# Attack-surface sweep (%s mode)\n\n", sum.Mode)
	fmt.Fprintf(w, "Hosts: %d  Open ports: %d  Findings: %d  Exploited: %d\n\n",
		sum.HostsScanned, sum.OpenPorts, sum.Findings, sum.Exploited)

	if len(ws.Subdomains) > 0 {
		fmt.Fprintf(w, "## Subdomains (%d)\n%s\n\n", len(ws.Subdomains), strings.Join(ws.Subdomains, ", "))
	}

	for _, h := range ws.Hosts {
		fmt.Fprintf(w, "## %s\n", h.Host)
		if h.Tech != nil && len(h.Tech.Technologies) > 0 {
			fmt.Fprintf(w, "- Tech: %s\n", strings.Join(h.Tech.Technologies, ", "))
		}
		if len(h.WAF) > 0 {
			fmt.Fprintf(w, "- WAF: %s\n", strings.Join(h.WAF, ", "))
		}
		if h.TLS != nil && len(h.TLS.Issues) > 0 {
			fmt.Fprintf(w, "- TLS issues: %s\n", strings.Join(h.TLS.Issues, "; "))
		}
		for _, p := range h.Ports {
			line := fmt.Sprintf("- %d/%s", p.Port, p.Service)
			if p.Banner != "" {
				line += " — " + p.Banner
			}
			fmt.Fprintln(w, line)
			for _, v := range p.Vulns {
				flag := ""
				if v.ExploitAvailable {
					flag = " [exploit]"
				}
				fmt.Fprintf(w, "    - %s (%s) %s%s\n", v.CVE, v.Severity, v.Title, flag)
			}
		}
		for _, f := range h.Findings {
			fmt.Fprintf(w, "- [%s] %s (%s)\n", f.Severity, f.Title, f.Source)
		}
		for _, e := range h.Exploits {
			fmt.Fprintf(w, "- EXPLOIT %s -> %s: %s\n", e.Module, e.Status, e.Detail)
		}
		fmt.Fprintln(w)
	}

	if len(sum.Errors) > 0 {
		fmt.Fprintf(w, "## Errors (%d)\n", len(sum.Errors))
		for _, e := range sum.Errors {
			fmt.Fprintf(w, "- %s\n", e)
		}
	}
}
