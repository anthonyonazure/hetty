import ExpandMoreIcon from "@mui/icons-material/ExpandMore";
import {
  Accordion,
  AccordionDetails,
  AccordionSummary,
  Box,
  Chip,
  Divider,
  Link as MuiLink,
  Typography,
} from "@mui/material";

interface Entry {
  title: string;
  category: string;
  what: string;
  how: string;
  good: string;
  bad: string;
  chain: string;
}

const ENTRIES: Entry[] = [
  {
    title: "Proxy (intercept + logs)",
    category: "Core",
    what: "A man-in-the-middle HTTP/S proxy. Every request your browser makes flows through Hetty so you can see, pause, and tamper with it. This is the foundation — most other tools work on traffic the proxy captured.",
    how: "Set your browser's proxy to 127.0.0.1:8080 and trust Hetty's CA cert (~/.hetty/hetty_cert.pem). Browse the target normally. Use Proxy → Logs to review traffic and Proxy → Intercept to pause/edit requests in flight.",
    good: "You see the site's real requests, cookies, tokens and API calls. Right-click any request to send it to Sender, Intruder, or Scanner.",
    bad: "No traffic showing up = the proxy isn't set in the browser or the CA isn't trusted (you'll see TLS errors). Fix the cert first.",
    chain:
      "Capture a request here → send to Scanner (find vulns), Intruder (fuzz a parameter), or Sender (hand-edit and replay).",
  },
  {
    title: "Scanner",
    category: "Core",
    what: "Automated vulnerability scanner. Runs passive checks (reads responses for problems) and active checks (sends payloads: XSS, SQLi, SSTI, command injection, path traversal, open redirect, host-header injection, etc.).",
    how: "Send a request from the proxy/sender to the Scanner, or use a headless scan (hetty scan --target). Review issues by severity.",
    good: "Findings come with severity, confidence, evidence and the exact request/response. 'Certain' confidence + 'high' severity = investigate first.",
    bad: "'Tentative' confidence can be a false positive — always confirm by replaying the request in Sender. Zero findings doesn't mean secure; it means these checks didn't fire.",
    chain:
      "Confirm a finding in Sender → if it's injectable, weaponize in Intruder → generate a CSRF/clickjacking PoC in PoC Generators → triage with the AI Analyst.",
  },
  {
    title: "Intruder",
    category: "Core",
    what: "Automated request fuzzer. Mark positions in a request with §markers§ and blast payload lists at them (sniper / battering-ram / pitchfork / cluster-bomb attack types).",
    how: "Send a request to Intruder, mark the injection point(s), pick payloads (bundled wordlists or your own), run. Sort results by status/length to spot anomalies.",
    good: "A response with a different length or status than the others usually means you hit something — an auth bypass, an IDOR, a valid value.",
    bad: "All responses identical = the parameter probably isn't reflected/used, or there's a WAF. Check the WAF tab.",
    chain: "Recon/Discovery finds the endpoint → Intruder fuzzes its parameters → confirmed issues go to the report.",
  },
  {
    title: "Recon: Subdomains",
    category: "Recon",
    what: "Finds subdomains of a domain via Certificate Transparency logs (crt.sh), optionally resolving them via DNS. More subdomains = more attack surface.",
    how: "Recon → Subdomains → enter a domain → Enumerate. Toggle Resolve to see which are live (have an IP).",
    good: "A long list with several 'live' hosts — especially dev/staging/admin/api hosts, which are often less hardened.",
    bad: "Empty result is usually crt.sh rate-limiting, not 'no subdomains'. Retry, or install subfinder/amass and use External Tools for more sources.",
    chain:
      "Subdomains → fingerprint + port-scan each live host → screenshot them all → feed into a workspace in Attack Surface.",
  },
  {
    title: "Recon: Port Scan / TLS / WAF / Fingerprint / Screenshot / Shodan",
    category: "Recon",
    what: "Native single-host tools: open ports + banners, TLS/cert weaknesses, WAF detection, technology fingerprint, a page screenshot, and Shodan OSINT lookups by IP.",
    how: "Recon → pick the tab → enter a host/URL → run. Port Scan has a Full (1-1024) toggle; Shodan needs --shodan-key set.",
    good: "Port scan: unexpected open ports (databases on 3306/5432/27017, admin panels on 8080/9000). TLS: 'self-signed' or 'TLS 1.0 supported' are real findings. WAF: knowing the WAF tells you how careful to be.",
    bad: "TLS 'no issues' and a clean fingerprint just mean nothing obvious — keep going. A detected WAF means your payloads may be blocked (expect 403s in Intruder).",
    chain:
      "Fingerprint tells you the stack → match it against known CVEs (the scanner/vulnmatch does this) → if a service+version is exploitable, Attack Surface NUKE mode can auto-exploit it.",
  },
  {
    title: "Attack Surface (Sn1per-style sweeps)",
    category: "Platform",
    what: "The orchestrator. A workspace holds targets; a scan mode chains the recon tools automatically: RECON (subdomains+ports+TLS+WAF+fingerprint), WEB (fingerprint+WAF+web vuln scan+screenshot), FULL (both), NUKE (full + Metasploit auto-exploitation).",
    how: "Attack Surface → create a workspace + targets → pick a mode → Run. Results land as per-host cards. NUKE needs --msf-url and an explicit Allow-exploit toggle.",
    good: "Host cards show everything at a glance: open ports with matched CVEs (⚡ = exploit available), tech, WAF, TLS issues, web findings, screenshots.",
    bad: "An empty card = the target didn't respond or isn't reachable. crt.sh errors show under the run summary and are safe to ignore.",
    chain:
      "This IS the chain. Use it as the one-click 'scan everything', then drill into specific findings with the individual tools.",
  },
  {
    title: "External Tools",
    category: "Platform",
    what: "Runs the real Kali/ProjectDiscovery arsenal (nmap, nuclei, subfinder, httpx, dalfox, sqlmap, gitleaks, ...) when installed on your machine, with live output. 55 tools detected on PATH.",
    how: "External Tools → pick a tool (grayed = not installed) → target → optional extra args → Run. Output streams live; Stop cancels.",
    good: "Real tool output, same as the terminal. nmap service/versions, nuclei findings, subfinder host lists.",
    bad: "'not installed' = the binary isn't on PATH (install it, e.g. apt/go install). A non-zero exit still shows captured output — read it; many tools 'fail' but printed useful results.",
    chain:
      "Discover hosts with subfinder → probe with httpx → scan with nuclei. Or wire these into a Workflow so they run as a chain.",
  },
  {
    title: "Workflows",
    category: "Platform",
    what: "Named chains of steps (native engines + external tools) run in order against a target. Built-ins cover the common engagement flows; you can build your own.",
    how: "Workflows → set a target → Run a built-in (Quick recon, Subdomain sweep, Web app audit, Full attack surface) or build a custom chain step-by-step and save it.",
    good: "One report with every step's output, in the order a pro would run them. Repeatable across targets.",
    bad: "A step shows 'error' if its tool isn't installed — the chain continues; install the tool or swap it for a native step.",
    chain: "A saved workflow can be scheduled in Monitoring (kind = workflow) to run on a timer.",
  },
  {
    title: "Monitoring (the force multiplier)",
    category: "Platform",
    what: "Schedules a check to re-run on a timer and diffs each run against the last — so you find out what's NEW (a fresh subdomain, a newly open port, a new finding) automatically. In bug bounty, the delta is where the money is.",
    how: "Monitoring → add a monitor (target, check type, interval, optional Slack/Discord/webhook alert URL) → enable. The first run is a baseline; later runs report changes. Use 'Changes' to see history.",
    good: "An alert that says '+ dev.target.com appeared' or '+ port:6379/redis' — that's a new exposure, often before the target notices.",
    bad: "Nothing changing is normal and good. Set a sane interval (hourly/daily) — too-frequent scans are noisy and can get you rate-limited or blocked.",
    chain:
      "Point a monitor at a workspace/workflow/tool. Pair with an alert webhook so you're notified the moment your surface changes.",
  },
  {
    title: "Save / Storage",
    category: "Platform",
    what: "Pluggable destinations for reports, exports and monitoring snapshots: local folder, network share (UNC), S3-compatible, Azure Blob, Google Drive, Box.",
    how: "Save / Storage → add a destination (pick kind, fill creds) → Test to verify. Other features save to it by name.",
    good: "'Test write OK → <location>' means creds and connectivity are good.",
    bad: "A test failure shows the provider error (bad key, wrong bucket/region, expired token). Cloud tokens (Drive/Box) expire — refresh them.",
    chain: "Run a scan/workflow → export the report → save to a destination → share the cloud link with your team.",
  },
  {
    title: "Macros, WS Repeater, PoC, Templates",
    category: "Specialist",
    what: "Macros: scripted login sequences (keep the scanner authenticated). WS Repeater: send/replay WebSocket frames. PoC Generators: CSRF + clickjacking proof pages. Templates: nuclei-style YAML detections.",
    how: "Each has its own page. Macros: define request steps + extractors, run, optionally save as a session profile. PoC: paste a request, generate the HTML. Templates: run built-ins or paste inline YAML.",
    good: "Macro returns the right cookies/token; PoC HTML auto-submits to the victim endpoint; a template matches with the expected severity.",
    bad: "A macro that returns no token means an extractor regex is wrong. A PoC that doesn't fire usually needs the right content-type (form vs fetch).",
    chain:
      "Macro keeps you authenticated → Scanner/Intruder hit protected endpoints → confirmed CSRF → PoC Generators produces the report artifact.",
  },
];

export default function Guide(): JSX.Element {
  const categories = Array.from(new Set(ENTRIES.map((e) => e.category)));

  return (
    <Box sx={{ maxWidth: 900 }}>
      <Typography variant="h4" sx={{ mb: 1 }}>
        Guide
      </Typography>
      <Typography variant="body2" color="text.secondary" sx={{ mb: 3 }}>
        New to this? Read top to bottom. Each tool explains what it is, exactly how to use it, how to tell a good result
        from a bad one, and how to chain it with the others. The short version of the whole platform:{" "}
        <strong>Proxy</strong> captures traffic → <strong>Recon / Attack Surface</strong> maps the target →{" "}
        <strong>Scanner / Intruder / External Tools</strong> find issues → <strong>Workflows</strong> chain it all →{" "}
        <strong>Monitoring</strong> tells you what changed → <strong>Save</strong> ships the report.
      </Typography>

      {categories.map((cat) => (
        <Box key={cat} sx={{ mb: 2 }}>
          <Divider sx={{ mb: 1 }}>
            <Chip label={cat} />
          </Divider>
          {ENTRIES.filter((e) => e.category === cat).map((e) => (
            <Accordion key={e.title} disableGutters>
              <AccordionSummary expandIcon={<ExpandMoreIcon />}>
                <Typography variant="subtitle1">{e.title}</Typography>
              </AccordionSummary>
              <AccordionDetails>
                <Section label="What it is" text={e.what} />
                <Section label="How to use it" text={e.how} />
                <Section label="A good result looks like" text={e.good} color="success.main" />
                <Section label="A bad / empty result means" text={e.bad} color="warning.main" />
                <Section label="Chain it with" text={e.chain} color="primary.main" />
              </AccordionDetails>
            </Accordion>
          ))}
        </Box>
      ))}

      <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
        Tip: this whole platform draws on ideas from{" "}
        <MuiLink href="https://github.com/projectdiscovery" target="_blank" rel="noreferrer">
          ProjectDiscovery
        </MuiLink>
        , reNgine, Osmedeus and Sn1per — if you install their CLI tools, they light up under External Tools and in
        Workflows automatically.
      </Typography>
    </Box>
  );
}

function Section({ label, text, color }: { label: string; text: string; color?: string }): JSX.Element {
  return (
    <Box sx={{ mb: 1.5 }}>
      <Typography
        variant="caption"
        sx={{ fontWeight: 700, color: color || "text.primary", textTransform: "uppercase", letterSpacing: 0.5 }}
      >
        {label}
      </Typography>
      <Typography variant="body2">{text}</Typography>
    </Box>
  );
}
