package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/oklog/ulid"
	"github.com/peterbourgon/ff/v3/ffcli"

	"github.com/dstotijn/hetty/pkg/report"
	"github.com/dstotijn/hetty/pkg/scan"
	"github.com/dstotijn/hetty/pkg/spider"
)

// memScanRepo is an in-memory scan.Repository for headless scans — no database
// is needed for a one-shot CI run.
type memScanRepo struct {
	mu     sync.Mutex
	issues map[string][]scan.Issue
}

func newMemScanRepo() *memScanRepo {
	return &memScanRepo{issues: make(map[string][]scan.Issue)}
}

func (r *memScanRepo) StoreIssue(_ context.Context, issue scan.Issue) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := issue.ProjectID.String()
	r.issues[k] = append(r.issues[k], issue)
	return nil
}

func (r *memScanRepo) FindIssues(_ context.Context, projectID ulid.ULID) ([]scan.Issue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]scan.Issue(nil), r.issues[projectID.String()]...), nil
}

func (r *memScanRepo) FindIssueByID(_ context.Context, projectID, id ulid.ULID) (scan.Issue, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, is := range r.issues[projectID.String()] {
		if is.ID.Compare(id) == 0 {
			return is, nil
		}
	}
	return scan.Issue{}, fmt.Errorf("issue not found")
}

func (r *memScanRepo) ClearIssues(_ context.Context, projectID ulid.ULID) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.issues, projectID.String())
	return nil
}

// scanParams holds the resolved options for a headless scan.
type scanParams struct {
	target   string
	crawl    bool
	depth    int
	maxPages int
	rate     float64
	timeout  time.Duration
}

//nolint:gosec
var scanEntropy = rand.New(rand.NewSource(time.Now().UnixNano()))

func scanULID() ulid.ULID {
	return ulid.MustNew(ulid.Timestamp(time.Now()), scanEntropy)
}

// runScan performs the headless scan and returns the findings. It is the
// testable core of the `hetty scan` subcommand.
func runScan(ctx context.Context, p scanParams) ([]scan.Issue, error) {
	base, err := url.Parse(p.target)
	if err != nil || base.Scheme == "" || base.Host == "" {
		return nil, fmt.Errorf("hetty scan: --target must be an absolute URL")
	}

	opts := scan.DefaultOptions()
	opts.PassiveOnProxy = false
	if p.timeout > 0 {
		opts.RequestTimeout = p.timeout
	}
	opts.RequestsPerSecond = p.rate

	svc := scan.NewService(scan.Config{Repository: newMemScanRepo(), Options: opts})
	projectID := scanULID()

	var templates []*scan.RequestTemplate
	if p.crawl {
		res, err := spider.New().Crawl(ctx, p.target, spider.Options{
			MaxDepth: p.depth, MaxPages: p.maxPages, SameHostOnly: true, RequestsPerSecond: p.rate,
		})
		if err != nil {
			return nil, fmt.Errorf("hetty scan: crawl failed: %w", err)
		}
		fmt.Fprintf(os.Stderr, "crawled %d page(s)\n", len(res.Pages))
		for _, u := range res.URLs {
			parsed, err := url.Parse(u)
			if err != nil {
				continue
			}
			templates = append(templates, scan.NewRequestTemplate(http.MethodGet, parsed, "", http.Header{}, nil))
		}
	} else {
		templates = []*scan.RequestTemplate{scan.NewRequestTemplate(http.MethodGet, base, "", http.Header{}, nil)}
	}

	fmt.Fprintf(os.Stderr, "scanning %d URL(s)...\n", len(templates))
	result, err := svc.ScanRequests(ctx, projectID, templates)
	if err != nil {
		return nil, fmt.Errorf("hetty scan: %w", err)
	}
	return result.Issues, nil
}

func renderReport(format string, issues []scan.Issue) (string, error) {
	now := time.Now()
	switch format {
	case "md", "markdown":
		return report.Markdown("Hetty Scan Report", issues, now), nil
	case "html":
		return report.HTML("Hetty Scan Report", issues, now), nil
	case "json":
		b, err := json.MarshalIndent(map[string]interface{}{"issues": issues}, "", "  ")
		return string(b), err
	default:
		return "", fmt.Errorf("hetty scan: invalid --format %q (use md, html or json)", format)
	}
}

var severityThresholds = map[string]int{
	"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4,
}

func severityRankCLI(s scan.Severity) int {
	if v, ok := severityThresholds[string(s)]; ok {
		return v
	}
	return 4
}

// scanCommand is the `hetty scan` headless CI subcommand.
type scanCommand struct {
	target   string
	crawl    bool
	depth    int
	maxPages int
	failOn   string
	format   string
	output   string
	rate     float64
	timeout  int
}

func newScanCommand() *ffcli.Command {
	c := &scanCommand{}
	fs := flag.NewFlagSet("hetty scan", flag.ExitOnError)
	fs.StringVar(&c.target, "target", "", "Target URL to scan (required).")
	fs.BoolVar(&c.crawl, "crawl", false, "Crawl the target first, then scan every discovered page.")
	fs.IntVar(&c.depth, "depth", 2, "Crawl depth (with --crawl).")
	fs.IntVar(&c.maxPages, "max-pages", 50, "Maximum pages to crawl (with --crawl).")
	fs.StringVar(&c.failOn, "fail-on", "",
		"Exit non-zero (code 2) if any finding is at or above this severity: info|low|medium|high|critical.")
	fs.StringVar(&c.format, "format", "md", "Report format: md, html or json.")
	fs.StringVar(&c.output, "output", "", "Write the report to this file (default: stdout).")
	fs.Float64Var(&c.rate, "rate", 0, "Request-rate cap (requests/sec). 0 = unthrottled.")
	fs.IntVar(&c.timeout, "timeout", 20, "Per-request timeout in seconds.")

	return &ffcli.Command{
		Name:       "scan",
		ShortUsage: "hetty scan --target <url> [flags]",
		ShortHelp:  "Run a headless scan against a target and emit a report (CI-friendly).",
		FlagSet:    fs,
		Exec:       c.Exec,
	}
}

func (c *scanCommand) Exec(ctx context.Context, _ []string) error {
	if c.target == "" {
		return fmt.Errorf("hetty scan: --target is required")
	}
	if c.failOn != "" {
		if _, ok := severityThresholds[c.failOn]; !ok {
			return fmt.Errorf("hetty scan: invalid --fail-on %q (info|low|medium|high|critical)", c.failOn)
		}
	}

	issues, err := runScan(ctx, scanParams{
		target:   c.target,
		crawl:    c.crawl,
		depth:    c.depth,
		maxPages: c.maxPages,
		rate:     c.rate,
		timeout:  time.Duration(c.timeout) * time.Second,
	})
	if err != nil {
		return err
	}

	rendered, err := renderReport(c.format, issues)
	if err != nil {
		return err
	}

	if c.output != "" {
		if err := os.WriteFile(c.output, []byte(rendered), 0o600); err != nil {
			return fmt.Errorf("hetty scan: write report: %w", err)
		}
		fmt.Fprintf(os.Stderr, "report written to %s\n", c.output)
	} else {
		fmt.Println(rendered)
	}

	fmt.Fprintf(os.Stderr, "%d finding(s)\n", len(issues))

	// CI gate: exit 2 if any finding meets or exceeds the threshold severity.
	if c.failOn != "" {
		threshold := severityThresholds[c.failOn]
		for _, is := range issues {
			if severityRankCLI(is.Severity) <= threshold {
				fmt.Fprintf(os.Stderr, "FAIL: finding %q (%s) is at or above the --fail-on threshold (%s)\n",
					is.Name, is.Severity, c.failOn)
				os.Exit(2)
			}
		}
	}

	return nil
}
