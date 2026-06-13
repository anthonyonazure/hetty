<img src="https://user-images.githubusercontent.com/983924/156430531-6193e187-7400-436b-81c6-f86862783ea5.svg#gh-light-mode-only" width="240"/>
<img src="https://user-images.githubusercontent.com/983924/156430660-9d5bd555-dcfd-47e2-ba70-54294c20c1b4.svg#gh-dark-mode-only" width="240"/>

[![Documentation](https://img.shields.io/badge/hetty-docs-25ae8f)](https://hetty.xyz/)
[![License](https://img.shields.io/github/license/dstotijn/hetty?color=25ae8f)](LICENSE)

> **This is an extended fork of [dstotijn/hetty](https://github.com/dstotijn/hetty).**
> Upstream Hetty is a Burp-Suite-style HTTP intercepting proxy. This fork keeps
> all of that and grows it into a single-binary offensive platform: it folds in
> an attack-surface engine (Sn1per / reNgine / Osmedeus style), native recon,
> a nuclei-compatible template scanner, continuous monitoring, distributed
> fan-out scanning, pluggable cloud save backends, optional Metasploit
> auto-exploitation, an AI analyst, and an MCP server — all dependency-light Go,
> no Burp/Kali license required.

**Hetty** is an HTTP toolkit for security research. It started as an open-source
alternative to commercial software like Burp Suite Pro, and this fork extends it
into a full offensive-security workbench for the infosec and bug-bounty
community — proxy and manual tooling on one side, automated attack-surface
discovery and scanning on the other, with everything correlated into a single
project database.

<img src="https://hetty.xyz/img/hero.png" width="907" alt="Hetty proxy logs (screenshot)" />

## Features

Everything below is available from the web dashboard and via a JSON/REST API
mounted alongside the GraphQL endpoint. Tools persist their state to the project
database and survive restarts.

### Proxy & manual testing (the Burp-style core)

- **Machine-in-the-middle (MITM) HTTP proxy**, with logs and advanced search
- **HTTP client / Sender (repeater)** for manually creating, editing and
  replaying proxied requests
- **Intercept** requests and responses for manual review (edit, send/receive,
  cancel)
- **Scope support** and **project-based database storage** to keep work organized
- **Match & Replace** rules that rewrite proxied requests/responses
- **Macros** and a **WebSocket Repeater** for composing and replaying traffic
- **WebSocket interception** — the proxy parses and logs WS frames; history is
  browsable in the dashboard
- **Request annotations**, **rate limiting**, **upstream-proxy chaining**, and
  **"Send to" tool routing** (Scanner / Intruder / Authz from any log row)

### Scanning & exploitation

- **Active & passive vulnerability scanner** with a built-in check library
  (reflected XSS, error-based SQLi, time-based OS command injection, path
  traversal/LFI, SSTI, CRLF/header injection, open redirect, and out-of-band
  blind detection — plus passive checks for missing security headers, insecure
  cookies, banner and verbose-error disclosure, and directory listings)
- **Templated scanner** — a nuclei-compatible YAML engine (status / word / regex
  matchers) so Hetty can consume the community template ecosystem
- **Intruder** — automated payload attacks (sniper, battering ram, pitchfork,
  cluster bomb) with payload processors and response grep match/extract
- **Crawler/spider** (static) plus a **JS-rendering crawler** (headless Chrome)
  for SPA endpoints, with one-click crawl-and-audit
- **Out-of-band (OOB) collaborator** for blind detection, over HTTP and
  (optionally) DNS
- **Metasploit driver** (optional) — auto-exploitation via an external MSF RPC
  endpoint, gated behind explicit flags and `nuke`/`--exploit` mode

### Attack-surface management & recon (Sn1per / reNgine style)

- **Attack-surface sweeps** — a scan-mode orchestrator (`recon` / `web` / `full`
  / `nuke`) that chains recon, port, TLS, WAF, web-scan, screenshot, vuln-match
  and (optionally) Metasploit into one command, with persistent workspaces
- **Native recon** — subdomain enumeration from Certificate Transparency logs
  (crt.sh), live-host resolution, and WhatWeb-style technology fingerprinting
- **Native port scanner** — TCP connect scan with banner grabbing and service ID
  (no nmap dependency)
- **Native TLS/SSL analyzer** — protocol-version probing and weak-cert/cipher
  flags (no sslscan/testssl)
- **WAF fingerprinting** (wafw00f-style) against a signature database
- **Vulnerability matching** — maps product/version banners to known vulns
  (offline searchsploit/vulners style) to prioritize and feed auto-exploitation
- **OSINT** — Shodan host lookups (key-gated)
- **Screenshots** — headless-Chrome PNG capture (gowitness/eyewitness style) to
  build a gallery of discovered live hosts
- **Unified asset graph** — domains, hosts, URLs, services and findings, each
  with first-/last-seen timestamps, observing sources, attributes and parent
  links, correlated into one queryable graph that grows over time

### Web-app recon & specialist tooling

- **Content discovery** — recursive forced browsing with bundled wordlists and
  soft-404 calibration
- **Site map** — host→path tree aggregating proxy, spider and discovery traffic
  with observed parameters and detected technology
- **JavaScript recon** — passive mining of proxied JS for endpoints and leaked
  secrets (LinkFinder / SecretFinder style), backed by a curated secrets DB
- **Parameter discovery** — Param Miner-style hidden-parameter brute forcing
  (query/body/header) with reflection and behavior-change detection
- **GraphQL tooling** — introspection, schema browsing, generated query skeletons
- **JWT editor** — re-sign edited claims, forge `alg:none`, HS/RS key confusion,
  and weak-secret brute force
- **Request smuggling probe** — timing-based CL.TE / TE.CL desync detection
- **Authorization tester** (Autorize-style) — replays a request under other
  identities to find IDOR / BOLA / broken access control
- **Auth profiles & session handling** — named identities (headers, cookies,
  bearer, CSRF-token macro) and **login macros** (session flows) applied by the
  authorization tester, scanner and intruder so automated requests run
  authenticated
- **Decoder** (URL, Base64, hex, HTML, gzip/zlib, JWT, MD5/SHA hashing, smart
  decode), **Comparer** (word/byte diff), **Sequencer** (token entropy analysis)
- **PoC generators** — auto-submitting CSRF pages and clickjacking overlays
  (Burp CSRF-PoC / Clickbandit style)

### Orchestration, scale & automation

- **Workflows** — chain tools into named, repeatable engagement sequences
  (recon → probe → scan), with prebuilt chains and user-defined ones aggregating
  into a single report
- **Continuous monitoring** — schedules re-run a probe on a timer, diff against
  the previous snapshot, and alert on change (new subdomain, newly open port,
  freshly vulnerable service) with auto-saved results
- **Distributed scanning** — a controller fans a target list out across
  registered Hetty worker instances and aggregates results (Axiom-style
  horizontal scaling, no cloud SDK)
- **External-tool framework** — runs the classic Kali/Sn1per arsenal (nuclei,
  trivy, ffuf, etc.) when present on `PATH`, building argv safely with no shell,
  capturing live output in the GUI — the hybrid escape hatch over the native
  fast path
- **Save / Storage backends (vault)** — write reports, exports and monitoring
  snapshots to a local folder, network share (UNC), S3-compatible storage, Azure
  Blob, Google Drive or Box, all implemented with the standard library only
- **AI analyst** (optional) — an LLM assistant that triages scanner findings
  (false-positive scoring), suggests payloads, and drafts proof-of-concept
  reports; enable with `--ai-key` or `ANTHROPIC_API_KEY`
- **MCP server** — `hetty mcp` exposes Hetty's engines as Model Context Protocol
  tools over stdio, so an AI agent (Claude Desktop, Claude Code) can drive scans,
  recon, param mining, GraphQL introspection, smuggling probes and more
- **Extension ecosystem** — JavaScript extensions with request/response hooks,
  custom active/passive scan checks, and registered custom actions
- **Findings export** — scanner issues as a standalone HTML or Markdown report
- **Headless / CI scanning** — `hetty scan` runs a crawl-and-audit from the CLI
  and fails the build on findings at or above a chosen severity
- **JSON/REST API** exposing every tool for automation

## Security tooling

Every tool is reachable from the web dashboard and over the JSON/REST API mounted
alongside the GraphQL endpoint:

| Tool | Endpoint(s) |
| --- | --- |
| Scanner | `POST /api/scanner/scan`, `GET/DELETE /api/scanner/issues`, `GET /api/scanner/checks` |
| Templated scanner | `GET /api/template`, `POST /api/template/run` |
| Crawl & audit | `POST /api/spider/crawl`, `POST /api/scanner/crawl-scan` |
| JS-rendering crawler | `POST /api/browser/crawl` |
| Intruder | `POST /api/intruder/positions`, `POST /api/intruder/run` |
| Decoder | `GET /api/decoder/codecs`, `POST /api/decoder`, `POST /api/decoder/smart` |
| Comparer | `POST /api/comparer` |
| Sequencer | `POST /api/sequencer` |
| Match & Replace | `GET/PUT /api/rules` |
| Macros | `GET/PUT/DELETE /api/macros`, `POST /api/macros/run` |
| WS Repeater | `POST /api/wsrepeater` |
| PoC generators | `POST /api/poc/csrf`, `POST /api/poc/clickjacking` |
| Findings export | `GET /api/scanner/report?format=html\|md` |
| Parameter discovery | `POST /api/paramminer` |
| GraphQL | `POST /api/gql/introspect` |
| Request smuggling | `POST /api/smuggle` |
| WebSocket history | `GET /api/websocket/connections`, `GET /api/websocket/messages`, `DELETE /api/websocket` |
| AI analyst | `GET /api/ai/status`, `POST /api/ai/triage`, `POST /api/ai/payloads`, `POST /api/ai/report` |
| Authorization tester | `POST /api/authz/analyze` |
| Auth profiles & sessions | `GET/PUT /api/session/profiles`, `DELETE /api/session/profiles?name=…` |
| Content discovery | `POST /api/discovery` |
| Wordlists | `GET /api/wordlists` |
| Site map | `GET/DELETE /api/sitemap`, `POST /api/sitemap/ingest` |
| JWT editor | `POST /api/jwt/parse`, `/api/jwt/sign`, `/api/jwt/alg-none`, `/api/jwt/brute` |
| Annotations | `GET/PUT /api/annotations`, `DELETE /api/annotations?id=…` |
| Extensions | `GET /api/extensions`, `POST /api/extensions/reload`, `GET /api/extensions/actions`, `POST /api/extensions/actions/run` |
| Collaborator | `POST /api/collab/token`, `GET /api/collab/interactions?token=…` |
| **Attack surface (ASM)** | `POST /api/asm/run`, `GET /api/asm/workspace`, `GET/PUT/DELETE /api/asm/workspaces` |
| **Recon** | `POST /api/recon/subdomains`, `POST /api/recon/fingerprint` |
| **Port scan** | `POST /api/portscan` |
| **TLS scan** | `POST /api/tlsscan` |
| **WAF detect** | `POST /api/wafdetect` |
| **OSINT** | `POST /api/osint/shodan` |
| **Screenshots** | `POST /api/screenshot` |
| **Asset graph** | `GET /api/assets`, `GET /api/assets/interesting`, `GET /api/assets/related`, `GET /api/assets/stats` |
| **Workflows** | `GET/PUT/DELETE /api/workflows`, `POST /api/workflows/run` |
| **Monitoring** | `GET/PUT/DELETE /api/monitor/schedules`, `POST /api/monitor/run`, `GET /api/monitor/diffs` |
| **Distributed** | `GET/PUT/DELETE /api/cluster/workers`, `POST /api/cluster/run` |
| **External tools** | `GET /api/exttools`, `POST /api/exttools/run`, `GET /api/exttools/job`, `POST /api/exttools/stop` |
| **Save / Storage (vault)** | `GET/PUT/DELETE /api/vault/destinations`, `POST /api/vault/save` |
| **Metasploit** | `GET /api/msf/status` |

The scanner persists issues per project, de-duplicating by fingerprint. Passive
checks also run automatically on all proxied traffic (including JavaScript recon
that mines proxied JS for endpoints and secrets). The collaborator records
out-of-band callbacks at `/oob/<token>` and is used by the scanner's blind
detection check; pass `--dns-addr :53 --dns-domain oob.example.com` to also
record DNS pingbacks for a delegated domain.

The authorization tester replays a request under stored auth profiles (and an
unauthenticated variant) and classifies each as **bypassed** / **enforced** /
**ambiguous** by comparing responses to the privileged baseline. Profiles are
managed under Auth Profiles and may carry a CSRF-token macro. Proxy-log rows
have **Send to Scanner / Intruder / Authz** actions, and the site map organizes
everything Hetty has seen into a per-host path tree.

### Attack-surface sweeps

The ASM engine chains the native recon, port, TLS, WAF, web-scan, screenshot and
vuln-match engines into one-command sweeps over a persistent workspace. Run it
headless from the CLI:

```console
$ hetty sweep --targets example.com,api.example.com --mode full
```

Modes escalate in depth: `recon` (discovery only) → `web` (recon + web scan) →
`full` (everything passive/active and safe) → `nuke` (adds Metasploit
auto-exploitation; requires `--exploit` and `--msf-url`). `--full-ports` widens
the port scan from the top 100 to ports 1–1024.

### Continuous monitoring

Monitoring turns the point-in-time tools into a watch: a schedule re-runs a probe
against a target on a timer, diffs the result against the previous snapshot, and
surfaces "what's new since last time" — a new subdomain, a newly open port, a
freshly vulnerable service. Results auto-save to the project (and to any
configured vault destination). Manage schedules under **Monitoring** or via
`/api/monitor/schedules`; a background scheduler runs them while the server is up.

### Distributed scanning

For large target lists, register additional Hetty instances as workers (each just
a Hetty exposing its REST API, optionally protected with `--auth-token`). The
controller fans the targets out across the pool, runs a scan kind on each, and
aggregates the results — Axiom-style horizontal scaling with no cloud-provider
SDK. Provision workers however you like; the controller only needs their URLs.
Configure under **Distributed** or via `/api/cluster/workers` and `/api/cluster/run`.

### External tools (hybrid arsenal)

When the classic command-line tools (nuclei, trivy, ffuf, and friends) are
installed on `PATH`, the **External Tools** page runs them for you: Hetty detects
availability, builds argv safely (no shell, so no metacharacter injection),
executes in the background, and streams live output into the GUI. Native engines
are the fast path; these wrappers add depth when the real tools are present.

### Save destinations (vault)

Reports, exports and monitoring snapshots can be written to a pluggable set of
destinations: a local folder, a network share (UNC path), S3-compatible object
storage, Azure Blob Storage, Google Drive or Box. Every backend is implemented
with the standard library only (raw HTTP + crypto), so Hetty stays a single
dependency-light binary. Configure under **Save / Storage** or via
`/api/vault/destinations`.

### MCP server

`hetty mcp` runs a Model Context Protocol server over stdio, exposing Hetty's
engines as tools an AI agent can call by natural language: `scan_url`,
`discover_content`, `mine_parameters`, `graphql_introspect`, `smuggle_probe`,
`recon_subdomains`, `fingerprint`, `run_templates`, and `decode`. Point Claude
Desktop, Claude Code, or any MCP client at it to drive Hetty conversationally.

### Headless / CI scanning

Run a scan from the command line without the proxy or web UI — useful in CI to
gate a build on newly introduced vulnerabilities:

```console
$ hetty scan --target https://staging.example.com/ --crawl --fail-on high --format md --output report.md
```

It crawls the target (with `--crawl`), actively scans every discovered page,
writes a report (`md`, `html` or `json`), and **exits with code 2** if any
finding is at or above the `--fail-on` severity — so a CI job fails when a
high/critical issue appears. `--rate` throttles requests to stay polite.

### Sidebar modes

The dashboard packs a lot of tools, so the sidebar supports **modes** that show
only a relevant subset. Built-in modes: **Everything**, **Recon**, **Web app**,
**Network**, **Platform**, and **Minimal** — and you can define your own custom
modes (persisted in the browser). Projects, Settings and the in-app Guide are
always visible.

### Releases

Cross-platform binaries are built with [GoReleaser](https://goreleaser.com)
(`.goreleaser.yaml`). The release hooks build and embed the admin frontend, then
compile static binaries for Linux, macOS and Windows (amd64/arm64):

```console
$ goreleaser build --snapshot --clean   # local test build
$ goreleaser release --clean            # tagged release
```

### Extensions

JavaScript extensions are loaded from `~/.hetty/extensions`. They interact with
Hetty through the `hetty` host API to hook proxied traffic, send requests,
register custom scan checks, and expose custom actions. See
[`examples/extensions`](examples/extensions/) for working samples and the full
API reference.

## Getting started

Because this is a fork, the upstream package managers (`brew`, `snap`, `scoop`)
install **vanilla** Hetty without the tooling above. To get this build, compile
from source.

### Build from source

Requirements: Go 1.25+ and Node/Yarn (to build the embedded admin frontend).

All the tooling above lives on the **`pentest-tooling`** branch (the default
`main` branch tracks vanilla upstream Hetty), so check that branch out:

```sh
git clone -b pentest-tooling https://github.com/anthonyonazure/hetty.git
cd hetty
make build          # builds the admin UI, embeds it, then `go build ./cmd/hetty`
./hetty             # run it
```

`make build` runs `yarn install && yarn run export` in `admin/`, moves the static
export into `cmd/hetty/admin`, and compiles a single self-contained binary
(`CGO_ENABLED=0`). Use `make clean` to reset build artifacts.

### Usage

Once built, start Hetty via:

```sh
hetty
```

Then open the admin interface (default `http://localhost:8080`), and configure
your browser/system to use Hetty as its HTTP proxy. The first run creates a root
CA certificate at `~/.hetty/hetty_cert.pem` — trust it so HTTPS interception
works.

To list all available options, run `hetty --help`:

```
Usage:
    hetty [flags] [subcommand] [flags]

Runs an HTTP server with (MITM) proxy, GraphQL service, and a web based admin interface.

Options:
    --cert            Path to root CA certificate. Creates file if it doesn't exist. (Default: "~/.hetty/hetty_cert.pem")
    --key             Path to root CA private key. Creates file if it doesn't exist. (Default: "~/.hetty/hetty_key.pem")
    --db              Database file path. Creates file if it doesn't exist. (Default: "~/.hetty/hetty.db")
    --addr            TCP address to listen on, in the form "host:port". (Default: ":8080")
    --chrome          Launch Chrome with proxy settings applied and certificate errors ignored. (Default: false)
    --rate            Global request-rate cap (req/sec) for scanner, intruder and spider. 0 = unthrottled.
    --upstream-proxy  Route outbound traffic through an upstream http://, https:// or socks5:// proxy.
    --auth-token      Require this token (Basic password, Bearer, or X-Hetty-Token) for the UI + API. Recommended off-localhost.
    --dns-addr        UDP address for the OOB DNS collaborator listener (e.g. ":53"). Disabled when empty.
    --dns-domain      Base domain delegated to the DNS collaborator (e.g. "oob.example.com").
    --ai-key          Anthropic API key enabling the AI analyst. Falls back to ANTHROPIC_API_KEY.
    --ai-model        Model for the AI analyst (default: claude-opus-4-8).
    --shodan-key      Shodan API key for OSINT host lookups. Falls back to SHODAN_API_KEY.
    --msf-url         Metasploit RPC endpoint for auto-exploitation (e.g. https://127.0.0.1:55553/api/). Disabled when empty.
    --msf-user        Metasploit RPC username. (Default: "msf")
    --msf-pass        Metasploit RPC password.
    --msf-insecure    Skip TLS verification for the Metasploit RPC endpoint. (Default: true)
    --verbose         Enable verbose logging.
    --json            Encode logs as JSON, instead of pretty/human readable output.
    --version, -v     Output version.
    --help, -h        Output this usage text.

Subcommands:
    - cert    Certificate management
    - scan    Run a headless scan against a target and emit a report (CI-friendly)
    - sweep   Run a headless attack-surface sweep (recon/web/full/nuke) and print a report
    - mcp     Run an MCP (Model Context Protocol) server exposing Hetty's tools over stdio

Run `hetty <subcommand> --help` for subcommand specific usage instructions.

Visit https://hetty.xyz to learn more about the upstream project.
```

> ⚠️ **Authorization.** This fork ships active scanning, exploitation and OOB
> collaborator features. Only point them at systems you own or are explicitly
> authorized to test. When binding to a non-localhost address, set `--auth-token`.

## Documentation

📖 The upstream proxy/UI docs at [hetty.xyz/docs](https://hetty.xyz/docs) cover
the core. Fork-specific tooling is documented in-app under the **Guide** tab.

## Acknowledgements

- **Hetty** is created by [David Stotijn (dstotijn)](https://github.com/dstotijn)
  and the Hetty contributors — this is a fork that builds on their excellent
  foundation. If you find the core useful, [sponsor the upstream
  author](https://github.com/sponsors/dstotijn).
- Thanks to the [Hacker101 community on Discord](https://www.hacker101.com/discord)
  for the encouragement and early feedback.
- The font used in the logo and admin interface is [JetBrains
  Mono](https://www.jetbrains.com/lp/mono/).

## License

[MIT](LICENSE)

© 2019–2025 Hetty Software, and fork contributors.
