package exttool

// builtinTools is the Sn1per-style arsenal. Each runs only if its binary is
// found on PATH. {target} is substituted with the user-supplied target; extra
// args entered in the UI are appended. No shell is used.
var builtinTools = []Tool{
	// --- Port / network scanning ---
	{Name: "nmap", Binary: "nmap", Category: "portscan", NeedsTarget: true,
		Description: "Service/version + default-script scan (top 1000 ports).",
		Args:        []string{"-sV", "-sC", "-T4", "--top-ports", "1000", "{target}"}},
	{Name: "nmap-full", Binary: "nmap", Category: "portscan", NeedsTarget: true,
		Description: "Full TCP port scan with service detection.",
		Args:        []string{"-sV", "-p-", "-T4", "{target}"}},
	{Name: "masscan", Binary: "masscan", Category: "portscan", NeedsTarget: true,
		Description: "Fast Internet-scale port scanner.",
		Args:        []string{"-p1-65535", "--rate", "1000", "{target}"}},

	// --- Web scanning ---
	{Name: "nikto", Binary: "nikto", Category: "web", NeedsTarget: true,
		Description: "Web server misconfiguration / known-vuln scanner.",
		Args:        []string{"-host", "{target}"}},
	{Name: "whatweb", Binary: "whatweb", Category: "web", NeedsTarget: true,
		Description: "Web technology fingerprinter.",
		Args:        []string{"{target}"}},
	{Name: "wafw00f", Binary: "wafw00f", Category: "web", NeedsTarget: true,
		Description: "Web application firewall fingerprinter.",
		Args:        []string{"{target}"}},
	{Name: "wpscan", Binary: "wpscan", Category: "web", NeedsTarget: true,
		Description: "WordPress security scanner.",
		Args:        []string{"--url", "{target}", "--no-banner"}},
	{Name: "nuclei", Binary: "nuclei", Category: "vuln", NeedsTarget: true,
		Description: "Template-based vulnerability scanner.",
		Args:        []string{"-u", "{target}", "-silent"}},
	{Name: "gobuster", Binary: "gobuster", Category: "web", NeedsTarget: true,
		Description: "Directory/file brute-forcer (pass -w <wordlist> in extra args).",
		Args:        []string{"dir", "-u", "{target}"}},
	{Name: "feroxbuster", Binary: "feroxbuster", Category: "web", NeedsTarget: true,
		Description: "Fast recursive content discovery.",
		Args:        []string{"-u", "{target}"}},
	{Name: "ffuf", Binary: "ffuf", Category: "web", NeedsTarget: true,
		Description: "Web fuzzer (pass -w <wordlist> in extra args).",
		Args:        []string{"-u", "{target}"}},

	// --- Subdomain / OSINT ---
	{Name: "subfinder", Binary: "subfinder", Category: "subdomain", NeedsTarget: true,
		Description: "Passive subdomain enumeration.",
		Args:        []string{"-d", "{target}", "-silent"}},
	{Name: "amass", Binary: "amass", Category: "subdomain", NeedsTarget: true,
		Description: "In-depth attack-surface / subdomain mapping.",
		Args:        []string{"enum", "-passive", "-d", "{target}"}},
	{Name: "sublist3r", Binary: "sublist3r", Category: "subdomain", NeedsTarget: true,
		Description: "Subdomain enumeration via search engines.",
		Args:        []string{"-d", "{target}"}},
	{Name: "theharvester", Binary: "theHarvester", Category: "osint", NeedsTarget: true,
		Description: "Emails, subdomains, and hosts from public sources.",
		Args:        []string{"-d", "{target}", "-b", "all"}},
	{Name: "fierce", Binary: "fierce", Category: "dns", NeedsTarget: true,
		Description: "DNS reconnaissance / subdomain brute.",
		Args:        []string{"--domain", "{target}"}},

	// --- TLS ---
	{Name: "sslscan", Binary: "sslscan", Category: "tls", NeedsTarget: true,
		Description: "Enumerate SSL/TLS ciphers and protocols.",
		Args:        []string{"{target}"}},
	{Name: "testssl", Binary: "testssl.sh", Category: "tls", NeedsTarget: true,
		Description: "Thorough TLS configuration testing.",
		Args:        []string{"{target}"}},

	// --- DNS / info ---
	{Name: "dnsrecon", Binary: "dnsrecon", Category: "dns", NeedsTarget: true,
		Description: "DNS enumeration and zone analysis.",
		Args:        []string{"-d", "{target}"}},
	{Name: "dig", Binary: "dig", Category: "dns", NeedsTarget: true,
		Description: "DNS lookup (ANY by default).",
		Args:        []string{"{target}", "ANY"}},
	{Name: "whois", Binary: "whois", Category: "info", NeedsTarget: true,
		Description: "WHOIS registration lookup.",
		Args:        []string{"{target}"}},

	// --- SMB ---
	{Name: "enum4linux", Binary: "enum4linux", Category: "smb", NeedsTarget: true,
		Description: "SMB / Windows enumeration.",
		Args:        []string{"-a", "{target}"}},
	{Name: "smbmap", Binary: "smbmap", Category: "smb", NeedsTarget: true,
		Description: "SMB share enumeration.",
		Args:        []string{"-H", "{target}"}},

	// --- Brute force / injection / exploit ---
	{Name: "hydra", Binary: "hydra", Category: "brute", NeedsTarget: true,
		Description: "Credential brute-forcer (supply service + -L/-P in extra args).",
		Args:        []string{"{target}"}},
	{Name: "sqlmap", Binary: "sqlmap", Category: "vuln", NeedsTarget: true,
		Description: "Automatic SQL-injection detection/exploitation.",
		Args:        []string{"-u", "{target}", "--batch"}},
	{Name: "searchsploit", Binary: "searchsploit", Category: "exploit", NeedsTarget: true,
		Description: "Search Exploit-DB (target = search term).",
		Args:        []string{"{target}"}},
	{Name: "gowitness", Binary: "gowitness", Category: "screenshot", NeedsTarget: true,
		Description: "Screenshot a URL.",
		Args:        []string{"single", "{target}"}},
}
