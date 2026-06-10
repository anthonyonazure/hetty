// Package report renders scanner issues into a shareable, self-contained
// document — the export step bug-bounty work needs to turn findings into a PoC
// writeup. It produces Markdown and a standalone HTML page (inline CSS, no
// external assets) grouped by severity.
package report

import (
	"fmt"
	"html"
	"sort"
	"strings"
	"time"

	"github.com/dstotijn/hetty/pkg/scan"
)

// severityRank orders severities most-to-least critical for grouping.
var severityRank = map[scan.Severity]int{
	scan.SeverityCritical: 0,
	scan.SeverityHigh:     1,
	scan.SeverityMedium:   2,
	scan.SeverityLow:      3,
	scan.SeverityInfo:     4,
}

func sortIssues(issues []scan.Issue) []scan.Issue {
	out := make([]scan.Issue, len(issues))
	copy(out, issues)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := severityRank[out[i].Severity], severityRank[out[j].Severity]
		if ri != rj {
			return ri < rj
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func counts(issues []scan.Issue) map[scan.Severity]int {
	c := map[scan.Severity]int{}
	for _, is := range issues {
		c[is.Severity]++
	}
	return c
}

var severityOrder = []scan.Severity{
	scan.SeverityCritical, scan.SeverityHigh, scan.SeverityMedium, scan.SeverityLow, scan.SeverityInfo,
}

// Markdown renders issues as a Markdown report. generatedAt is injected (rather
// than read from the clock) so output is deterministic and testable.
func Markdown(title string, issues []scan.Issue, generatedAt time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s\n\n", title)
	fmt.Fprintf(&b, "_Generated %s — %d finding(s)._\n\n", generatedAt.UTC().Format(time.RFC3339), len(issues))

	c := counts(issues)
	b.WriteString("## Summary\n\n")
	b.WriteString("| Severity | Count |\n| --- | --- |\n")
	for _, sev := range severityOrder {
		if c[sev] > 0 {
			fmt.Fprintf(&b, "| %s | %d |\n", sev, c[sev])
		}
	}
	b.WriteString("\n")

	for _, is := range sortIssues(issues) {
		fmt.Fprintf(&b, "## [%s] %s\n\n", strings.ToUpper(string(is.Severity)), is.Name)
		fmt.Fprintf(&b, "- **Confidence:** %s\n", is.Confidence)
		fmt.Fprintf(&b, "- **URL:** `%s %s`\n", is.Method, is.URL)
		if is.Param != "" {
			fmt.Fprintf(&b, "- **Parameter:** `%s`\n", is.Param)
		}
		if is.Payload != "" {
			fmt.Fprintf(&b, "- **Payload:** `%s`\n", is.Payload)
		}
		b.WriteString("\n")
		if is.Description != "" {
			fmt.Fprintf(&b, "%s\n\n", is.Description)
		}
		if is.Evidence != "" {
			fmt.Fprintf(&b, "**Evidence:**\n\n```\n%s\n```\n\n", is.Evidence)
		}
		if is.Remediation != "" {
			fmt.Fprintf(&b, "**Remediation:** %s\n\n", is.Remediation)
		}
	}

	return b.String()
}

const htmlStyle = `
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a1a;line-height:1.5}
h1{border-bottom:2px solid #eee;padding-bottom:.3rem}
.issue{border:1px solid #e2e2e2;border-radius:6px;padding:1rem 1.25rem;margin:1rem 0}
.sev{display:inline-block;padding:.1rem .5rem;border-radius:4px;color:#fff;font-size:.8rem;font-weight:600;text-transform:uppercase}
.critical{background:#7b1fa2}.high{background:#d32f2f}.medium{background:#f57c00}.low{background:#0288d1}.info{background:#757575}
code,pre{font-family:"JetBrains Mono",Consolas,monospace;background:#f5f5f5;border-radius:3px}
code{padding:.1rem .3rem}
pre{padding:.75rem;overflow:auto}
table{border-collapse:collapse}td,th{border:1px solid #ddd;padding:.3rem .75rem;text-align:left}
.meta{color:#666;font-size:.9rem}
`

// HTML renders issues as a standalone HTML document.
func HTML(title string, issues []scan.Issue, generatedAt time.Time) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"en\"><head><meta charset=\"utf-8\">")
	fmt.Fprintf(&b, "<title>%s</title><style>%s</style></head><body>", html.EscapeString(title), htmlStyle)
	fmt.Fprintf(&b, "<h1>%s</h1>", html.EscapeString(title))
	fmt.Fprintf(&b, "<p class=\"meta\">Generated %s — %d finding(s).</p>",
		generatedAt.UTC().Format(time.RFC3339), len(issues))

	c := counts(issues)
	b.WriteString("<h2>Summary</h2><table><tr><th>Severity</th><th>Count</th></tr>")
	for _, sev := range severityOrder {
		if c[sev] > 0 {
			fmt.Fprintf(&b, "<tr><td><span class=\"sev %s\">%s</span></td><td>%d</td></tr>", sev, sev, c[sev])
		}
	}
	b.WriteString("</table>")

	for _, is := range sortIssues(issues) {
		b.WriteString("<div class=\"issue\">")
		fmt.Fprintf(&b, "<h3><span class=\"sev %s\">%s</span> %s</h3>",
			is.Severity, is.Severity, html.EscapeString(is.Name))
		fmt.Fprintf(&b, "<p class=\"meta\">Confidence: %s</p>", html.EscapeString(string(is.Confidence)))
		fmt.Fprintf(&b, "<p><code>%s %s</code></p>", html.EscapeString(is.Method), html.EscapeString(is.URL))
		if is.Param != "" {
			fmt.Fprintf(&b, "<p>Parameter: <code>%s</code></p>", html.EscapeString(is.Param))
		}
		if is.Payload != "" {
			fmt.Fprintf(&b, "<p>Payload: <code>%s</code></p>", html.EscapeString(is.Payload))
		}
		if is.Description != "" {
			fmt.Fprintf(&b, "<p>%s</p>", html.EscapeString(is.Description))
		}
		if is.Evidence != "" {
			fmt.Fprintf(&b, "<p><strong>Evidence:</strong></p><pre>%s</pre>", html.EscapeString(is.Evidence))
		}
		if is.Remediation != "" {
			fmt.Fprintf(&b, "<p><strong>Remediation:</strong> %s</p>", html.EscapeString(is.Remediation))
		}
		b.WriteString("</div>")
	}

	b.WriteString("</body></html>")
	return b.String()
}
