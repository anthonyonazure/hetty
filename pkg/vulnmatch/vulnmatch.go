// Package vulnmatch maps a service product/version (from banners, fingerprints,
// or Shodan) to known vulnerabilities — a lightweight, offline searchsploit /
// vulners-style lookup used to prioritize and (with the Metasploit driver)
// auto-exploit findings.
package vulnmatch

import (
	"regexp"
	"strings"
)

// Vuln is a matched known vulnerability.
type Vuln struct {
	CVE              string `json:"cve"`
	Title            string `json:"title"`
	Severity         string `json:"severity"`
	Product          string `json:"product"`
	AffectedVersions string `json:"affectedVersions"`
	ExploitAvailable bool   `json:"exploitAvailable"`
	MSFModule        string `json:"msfModule,omitempty"`
}

type sig struct {
	product   string // lowercase substring to find in the product/banner
	maxVuln   string // versions <= this are vulnerable ("" = all versions)
	cve       string
	title     string
	severity  string
	exploit   bool
	msfModule string
}

var versionRe = regexp.MustCompile(`(\d+(?:\.\d+){1,3}(?:p\d+)?)`)

// Match returns known vulnerabilities for a product/version pair.
func Match(product, version string) []Vuln {
	return matchWith(strings.ToLower(product), version)
}

// MatchBanner parses a product/version out of a raw service banner (e.g.
// "Apache/2.4.49 (Unix)", "OpenSSH_7.4", "vsftpd 2.3.4") and matches it.
func MatchBanner(banner string) []Vuln {
	return matchWith(strings.ToLower(banner), versionRe.FindString(banner))
}

func matchWith(haystack, version string) []Vuln {
	var out []Vuln
	for _, s := range signatures {
		if !strings.Contains(haystack, s.product) {
			continue
		}
		if s.maxVuln != "" && version != "" && !versionLE(version, s.maxVuln) {
			continue
		}
		out = append(out, Vuln{
			CVE:              s.cve,
			Title:            s.title,
			Severity:         s.severity,
			Product:          s.product,
			AffectedVersions: affected(s.maxVuln),
			ExploitAvailable: s.exploit,
			MSFModule:        s.msfModule,
		})
	}
	return out
}

func affected(maxVuln string) string {
	if maxVuln == "" {
		return "all versions"
	}
	return "<= " + maxVuln
}

// versionLE reports whether version a <= version b, comparing numeric segments
// (non-digit separators are treated as boundaries; missing segments are 0).
func versionLE(a, b string) bool {
	as, bs := toSegments(a), toSegments(b)
	n := len(as)
	if len(bs) > n {
		n = len(bs)
	}
	for i := 0; i < n; i++ {
		var av, bv int
		if i < len(as) {
			av = as[i]
		}
		if i < len(bs) {
			bv = bs[i]
		}
		if av != bv {
			return av < bv
		}
	}
	return true // equal
}

var digitsRe = regexp.MustCompile(`\d+`)

func toSegments(v string) []int {
	parts := digitsRe.FindAllString(v, -1)
	out := make([]int, 0, len(parts))
	for _, p := range parts {
		n := 0
		for _, c := range p {
			n = n*10 + int(c-'0')
		}
		out = append(out, n)
	}
	return out
}
