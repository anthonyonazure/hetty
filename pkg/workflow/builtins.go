package workflow

// builtinWorkflows are common engagement chains. "native" steps use Hetty's own
// engines (always available); "tool" steps use external tools when installed.
var builtinWorkflows = []Workflow{
	{
		Name:        "Quick recon",
		Description: "Fingerprint + WAF + top-port scan + TLS check. All native, no external tools needed.",
		Builtin:     true,
		Steps: []Step{
			{Type: "native", Name: "fingerprint"},
			{Type: "native", Name: "wafdetect"},
			{Type: "native", Name: "portscan"},
			{Type: "native", Name: "tlsscan"},
		},
	},
	{
		Name:        "Subdomain sweep",
		Description: "Enumerate subdomains (native crt.sh + subfinder/assetfinder if installed), then probe which are live with httpx.",
		Builtin:     true,
		Steps: []Step{
			{Type: "native", Name: "subdomains"},
			{Type: "tool", Name: "subfinder"},
			{Type: "tool", Name: "assetfinder"},
			{Type: "tool", Name: "httpx"},
		},
	},
	{
		Name:        "Web app audit",
		Description: "Fingerprint, screenshot, crawl for endpoints, then run the native web vuln checks and nuclei.",
		Builtin:     true,
		Steps: []Step{
			{Type: "native", Name: "fingerprint"},
			{Type: "native", Name: "screenshot"},
			{Type: "tool", Name: "katana"},
			{Type: "native", Name: "webscan"},
			{Type: "tool", Name: "nuclei"},
		},
	},
	{
		Name:        "URL & content discovery",
		Description: "Pull archived URLs (gau/waybackurls), crawl (hakrawler), and brute directories.",
		Builtin:     true,
		Steps: []Step{
			{Type: "tool", Name: "gau"},
			{Type: "tool", Name: "waybackurls"},
			{Type: "tool", Name: "hakrawler"},
			{Type: "tool", Name: "dirsearch"},
		},
	},
	{
		Name:        "Full attack surface",
		Description: "Subdomains → live hosts (httpx) → port scan (naabu) → TLS → vuln scan (nuclei) → screenshots.",
		Builtin:     true,
		Steps: []Step{
			{Type: "native", Name: "subdomains"},
			{Type: "tool", Name: "httpx"},
			{Type: "tool", Name: "naabu"},
			{Type: "native", Name: "tlsscan"},
			{Type: "tool", Name: "nuclei"},
			{Type: "native", Name: "screenshot"},
		},
	},
}
