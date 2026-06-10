<img src="https://user-images.githubusercontent.com/983924/156430531-6193e187-7400-436b-81c6-f86862783ea5.svg#gh-light-mode-only" width="240"/>
<img src="https://user-images.githubusercontent.com/983924/156430660-9d5bd555-dcfd-47e2-ba70-54294c20c1b4.svg#gh-dark-mode-only" width="240"/>

[![Latest GitHub release](https://img.shields.io/github/v/release/dstotijn/hetty?color=25ae8f)](https://github.com/dstotijn/hetty/releases/latest)
[![Build Status](https://img.shields.io/endpoint.svg?url=https%3A%2F%2Factions-badge.atrox.dev%2Fdstotijn%2Fhetty%2Fbadge%3Fref%3Dmain&label=build&color=24ae8f)](https://github.com/dstotijn/hetty/actions/workflows/build-test.yml)
![GitHub download count](https://img.shields.io/github/downloads/dstotijn/hetty/total?color=25ae8f)
[![GitHub](https://img.shields.io/github/license/dstotijn/hetty?color=25ae8f)](https://github.com/dstotijn/hetty/blob/master/LICENSE)
[![Documentation](https://img.shields.io/badge/hetty-docs-25ae8f)](https://hetty.xyz/)

**Hetty** is an HTTP toolkit for security research. It aims to become an open
source alternative to commercial software like Burp Suite Pro, with powerful
features tailored to the needs of the infosec and bug bounty community.

<img src="https://hetty.xyz/img/hero.png" width="907" alt="Hetty proxy logs (screenshot)" />

## Features

- Machine-in-the-middle (MITM) HTTP proxy, with logs and advanced search
- HTTP client for manually creating/editing requests, and replay proxied requests
- Intercept requests and responses for manual review (edit, send/receive, cancel)
- Scope support, to help keep work organized
- Easy-to-use web based admin interface
- Project based database storage, to help keep work organized
- **Active & passive vulnerability scanner** with a built-in check library
  (reflected XSS, error-based SQLi, time-based OS command injection, path
  traversal/LFI, SSTI, CRLF/header injection, open redirect, and out-of-band
  blind detection — plus passive checks for missing security headers, insecure
  cookies, banner and verbose-error disclosure, and directory listings)
- **Intruder** — automated payload attacks (sniper, battering ram, pitchfork,
  cluster bomb) with payload processors and response grep match/extract
- **Crawler/spider** with one-click crawl-and-audit
- **Decoder** (URL, Base64, hex, HTML, gzip/zlib, JWT, MD5/SHA hashing, smart decode)
- **Comparer** (word/byte diff) and **Sequencer** (token entropy analysis)
- **Match & Replace** rules that rewrite proxied requests/responses
- **Authorization tester** (Autorize-style) — replays a request under other
  identities to find IDOR / BOLA / broken access control
- **Auth profiles & session handling** — named identities (headers, cookies,
  bearer, CSRF-token macro) applied by the authorization tester, scanner and
  intruder so automated requests run as an authenticated user
- **Content discovery** — recursive forced browsing with a built-in wordlist
  and soft-404 calibration
- **Site map** — host→path tree aggregating proxy, spider and discovery traffic
  with observed parameters and detected technology
- **JavaScript recon** — passive mining of proxied JS for endpoints and leaked
  secrets (LinkFinder/SecretFinder-style)
- **JWT editor** — re-sign edited claims, forge `alg:none`, HS/RS key confusion,
  and weak-secret brute force
- **Parameter discovery** — Param Miner-style hidden-parameter brute forcing
  (query/body/header) with reflection and behavior-change detection
- **GraphQL tooling** — introspection, schema browsing, and generated query
  skeletons
- **Request smuggling probe** — timing-based CL.TE / TE.CL desync detection
- **WebSocket interception** — the proxy parses and logs WS frames; history is
  browsable in the dashboard
- **Findings export** — scanner issues as a standalone HTML or Markdown report
- **Durable tool state** — the site map, auth profiles, annotations, OOB
  collaborator interactions and WebSocket history persist to the project
  database and survive restarts
- **AI analyst** (optional) — an LLM assistant that triages scanner findings
  (false-positive scoring), suggests payloads, and drafts proof-of-concept
  reports; enable with `--ai-key` or `ANTHROPIC_API_KEY`
- **Extension ecosystem** — JavaScript extensions with request/response hooks
  and custom active/passive scan checks
- **Out-of-band (OOB) collaborator** for blind vulnerability detection, over
  HTTP and (optionally) DNS
- **Request annotations**, **rate limiting**, and **"Send to" tool routing**
- **Headless / CI scanning** — `hetty scan` runs a crawl-and-audit from the
  command line and fails the build on findings at or above a chosen severity
- **JSON/REST API** exposing every tool for automation

## Security tooling

In addition to the proxy, request log, sender (repeater) and intercept tools,
Hetty ships a full suite of testing tools modeled on Burp Suite. Every tool is
available from the web dashboard and via a JSON/REST API mounted alongside the
GraphQL endpoint:

| Tool | Endpoint(s) |
| --- | --- |
| Scanner | `POST /api/scanner/scan`, `GET/DELETE /api/scanner/issues`, `GET /api/scanner/checks` |
| Crawl & audit | `POST /api/spider/crawl`, `POST /api/scanner/crawl-scan` |
| Intruder | `POST /api/intruder/positions`, `POST /api/intruder/run` |
| Decoder | `GET /api/decoder/codecs`, `POST /api/decoder`, `POST /api/decoder/smart` |
| Comparer | `POST /api/comparer` |
| Sequencer | `POST /api/sequencer` |
| Match & Replace | `GET/PUT /api/rules` |
| Findings export | `GET /api/scanner/report?format=html\|md` |
| Parameter discovery | `POST /api/paramminer` |
| GraphQL | `POST /api/gql/introspect` |
| Request smuggling | `POST /api/smuggle` |
| WebSocket history | `GET /api/websocket/connections`, `GET /api/websocket/messages`, `DELETE /api/websocket` |
| AI analyst | `GET /api/ai/status`, `POST /api/ai/triage`, `POST /api/ai/payloads`, `POST /api/ai/report` |
| Authorization tester | `POST /api/authz/analyze` |
| Auth profiles | `GET/PUT /api/session/profiles`, `DELETE /api/session/profiles?name=…` |
| Content discovery | `POST /api/discovery` |
| Site map | `GET/DELETE /api/sitemap`, `POST /api/sitemap/ingest` |
| JWT editor | `POST /api/jwt/parse`, `/api/jwt/sign`, `/api/jwt/alg-none`, `/api/jwt/brute` |
| Annotations | `GET/PUT /api/annotations`, `DELETE /api/annotations?id=…` |
| Extensions | `GET /api/extensions`, `POST /api/extensions/reload` |
| Collaborator | `POST /api/collab/token`, `GET /api/collab/interactions?token=…` |

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
Hetty through the `hetty` host API to hook proxied traffic, send requests, and
register custom scan checks. See [`examples/extensions`](examples/extensions/)
for working samples and the full API reference.

👷‍♂️ Hetty is under active development. Check the <a
href="https://github.com/dstotijn/hetty/projects/1">backlog</a> for the current
status.

📣 Are you pen testing professionaly in a team? I would love to hear your
thoughts on tooling via [this 5 minute
survey](https://forms.gle/36jtgNc3TJ2imi5A8). Thank you!

## Getting started

💡 The [Getting started](https://hetty.xyz/docs/getting-started) doc has more
detailed install and usage instructions.

### Installation

The quickest way to install and update Hetty is via a package manager:

#### macOS

```sh
brew install hettysoft/tap/hetty
```

#### Linux

```sh
sudo snap install hetty
```

#### Windows

```sh
scoop bucket add hettysoft https://github.com/hettysoft/scoop-bucket.git
scoop install hettysoft/hetty
```

#### Other

Alternatively, you can [download the latest release from
GitHub](https://github.com/dstotijn/hetty/releases/latest) for your OS and
architecture, and move the binary to a directory in your `$PATH`. If your OS is
not available for one of the package managers or not listed in the GitHub
releases, you can compile from source _(link coming soon)_.

#### Docker

Docker images are distributed via [GitHub's Container registry](https://github.com/dstotijn/hetty/pkgs/container/hetty)
and [Docker Hub](https://hub.docker.com/r/dstotijn/hetty). To run Hetty via with a volume for database and certificate
storage, and port 8080 forwarded:

```
docker run -v $HOME/.hetty:/root/.hetty -p 8080:8080 \
  ghcr.io/dstotijn/hetty:latest
```

### Usage

Once installed, start Hetty via:

```sh
hetty
```

💡 Read the [Getting started](https://hetty.xyz/docs/getting-started) doc for
more details.

To list all available options, run: `hetty --help`:

```
$ hetty --help

Usage:
    hetty [flags] [subcommand] [flags]

Runs an HTTP server with (MITM) proxy, GraphQL service, and a web based admin interface.

Options:
    --cert         Path to root CA certificate. Creates file if it doesn't exist. (Default: "~/.hetty/hetty_cert.pem")
    --key          Path to root CA private key. Creates file if it doesn't exist. (Default: "~/.hetty/hetty_key.pem")
    --db           Database file path. Creates file if it doesn't exist. (Default: "~/.hetty/hetty.db")
    --addr         TCP address for HTTP server to listen on, in the form \"host:port\". (Default: ":8080")
    --chrome       Launch Chrome with proxy settings applied and certificate errors ignored. (Default: false)
    --verbose      Enable verbose logging.
    --json         Encode logs as JSON, instead of pretty/human readable output.
    --version, -v  Output version.
    --help, -h     Output this usage text.

Subcommands:
    - cert  Certificate management

Run `hetty <subcommand> --help` for subcommand specific usage instructions.

Visit https://hetty.xyz to learn more about Hetty.
```

## Documentation

📖 [Read the docs](https://hetty.xyz/docs)

## Support

Use [issues](https://github.com/dstotijn/hetty/issues) for bug reports and
feature requests, and
[discussions](https://github.com/dstotijn/hetty/discussions) for questions and
troubleshooting.

## Community

💬 [Join the Hetty Discord server](https://discord.gg/3HVsj5pTFP)

## Contributing

Want to contribute? Great! Please check the [Contribution
Guidelines](CONTRIBUTING.md) for details.

## Acknowledgements

- Thanks to the [Hacker101 community on Discord](https://www.hacker101.com/discord)
  for the encouragement and early feedback.
- The font used in the logo and admin interface is [JetBrains
  Mono](https://www.jetbrains.com/lp/mono/).

## Sponsors

💖 Are you enjoying Hetty? You can [sponsor me](https://github.com/sponsors/dstotijn)!

## License

[MIT](LICENSE)

© 2019–2025 Hetty Software
