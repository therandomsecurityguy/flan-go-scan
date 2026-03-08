![Go-Gopher-Flan-small](https://github.com/user-attachments/assets/e08ec4c5-8619-4437-a043-af7ea4a035fb)

# flan

A swiss-army scanner in Go. Successor to [Flan Scan](https://github.com/cloudflare/flan).

## Features

- TCP port scanning with bounded concurrency
- 51-protocol service fingerprinting via [fingerprintx](https://github.com/praetorian-inc/fingerprintx) (SSH, HTTP, MySQL, Redis, RDP, PostgreSQL, and more)
- Technology detection (Wappalyzer) and CPE generation
- TLS certificate inspection (version, cipher, subject, issuer, SANs, expiry, self-signed)
- Optional strict TLS certificate verification via `--tls-verify`
- CVE lookup by CPE via NVD API
- Host discovery (TCP probe to skip dead hosts)
- Passive subdomain enumeration via 10 no-key sources (crt.sh, Common Crawl, Wayback Machine, RapidDNS, Anubis, Digitorus, HudsonRock, SiteDossier, THC, ThreatCrowd)
- CDN detection (Cloudflare) — limits scan to ports 80/443 by default on CDN hosts
- DNS enumeration with wildcard detection and custom wordlist/resolver support
- Cloudflare zone-based target discovery via `CLOUDFLARE_API_TOKEN`
- NS, MX, TXT, CNAME record lookups
- CIDR and stdin input support
- nmap top 100/1000 port lists with expanded 2000/5000 presets
- Scan checkpointing and resumption
- Scan guardrails for large runs (`max_targets`, `max_ports_per_target`, `max_duration`)
- Progress reporting
- UDP service detection (DNS, NTP, SNMP, IPSEC) via `--udp`
- Web crawler with app fingerprinting via `--crawl` (path, header, and cookie-based detection for 60+ CMSes, frameworks, and admin tools)
- Context-aware rate limiting and TLS inspection — clean shutdown on Ctrl+C
- Graceful shutdown on SIGINT/SIGTERM
- AI-powered security analysis via [Together API](https://together.ai) (DeepSeek V3.1) — brief summary on every scan, detailed report with `--analyze`
- Pretty streaming CLI output with TTY detection (JSONL when piping)
- Per-run scan metadata report (`scan-metadata-*.json`) for auditability
- JSON, JSONL (streaming), CSV, and text output
- Domain-mode output keeps subdomain and IP context (`hostname (ip):port`)
- Security header checks are evaluated on `2xx/3xx` HTTP responses; `4xx/5xx` responses are reported as skipped
- Configurable via YAML

## Installation

From GitHub:

```
go install github.com/therandomsecurityguy/flan-go-scan/cmd/flan@latest
```

From source (go version > 1.21):

```
git clone git@github.com:therandomsecurityguy/flan-go-scan.git
cd flan-go-scan
go build -o flan ./cmd/flan
./flan --help
```

Docker:

```
git clone git@github.com:therandomsecurityguy/flan-go-scan.git
cd flan-go-scan
docker build -t flan .
docker run --rm flan --help
docker run --rm flan -t scanme.nmap.org --json
```

## Usage

```
flan --help
```

Scan a single target:

```
flan -t scanme.nmap.org
```

Scan a domain (DNS enumeration + port scan):

```
flan -d example.com
```

Scan from a file with top 1000 ports:

```
flan -l targets.txt --top-ports 1000
```

Scan a CIDR range from stdin:

```
echo "10.0.0.0/24" | flan -l -
```

Scan with custom wordlist and resolver:

```
flan -d example.com -w wordlist.txt -r 8.8.8.8:53
```

Passive enumeration only (skip brute-force):

```
flan -d example.com --passive-only
```

Subdomains only output (subfinder-style, one per line):

```
flan -d example.com --subdomains-only
```

Domain scan port profile:

```
flan -d example.com --subdomain-ports web
```

Tune passive enumeration sources/settings:

```
flan -d example.com --subfinder-all --subfinder-max-time 10 --subfinder-threads 20
```

Scan all ports on CDN hosts (default is 80/443 only):

```
flan -d example.com --scan-cdn
```

Discover scan targets from Cloudflare zones:

```
flan --cloudflare --cloudflare-zones example.net --cloudflare-include api.example.net
```

Limit Cloudflare discovery to matching hostnames:

```
flan --cloudflare --cloudflare-zones example.net --cloudflare-include "api.example.net" --cloudflare-exclude "internal.example.net"
```

Print Cloudflare-discovered hostnames only:

```
flan --cloudflare --cloudflare-zones example.net --cloudflare-include "api.example.net" --subdomains-only
```

Write a normalized Cloudflare inventory snapshot for later diffing:

```
flan --cloudflare --cloudflare-zones example.net --cloudflare-include "api.example.net" --cloudflare-inventory-out reports/cloudflare-example-net.json
```

Diff the current Cloudflare inventory against a previous snapshot:

```
flan --cloudflare --cloudflare-zones example.net --cloudflare-include "api.example.net" --cloudflare-inventory-out reports/cloudflare-example-net.json --cloudflare-diff-against reports/cloudflare-example-net-prev.json
```

Scan only added/changed Cloudflare hosts when a previous snapshot exists:

```
flan --cloudflare --cloudflare-zones example.net --cloudflare-include "api.example.net" --cloudflare-inventory-out reports/cloudflare-example-net.json --cloudflare-delta-only
```

Enable UDP scanning:

```
flan -t scanme.nmap.org --udp
```

Crawl HTTP/HTTPS services for endpoints, sensitive paths, and app fingerprinting:

```
flan -t example.com --crawl
```

Crawl with custom depth:

```
flan -t example.com --crawl --crawl-depth 3
```

Scan with detailed AI-powered analysis (requires `TOGETHER_API_KEY`):

```
flan -t scanme.nmap.org --analyze
```

Use a custom asset context file for policy-aware AI analysis:

```
flan -t api.example.com --context /path/to/context.yaml
```

Context is automatically loaded from `config/context.yaml` when present. It defines asset criticality, data classification, and security policies (TLS minimum version, SSH auth requirements, allowed ports). Policy violations are flagged before AI analysis runs.

Header inspection behavior: security-header findings are generated for HTTP `2xx/3xx` responses. For `4xx/5xx` responses (common on load balancer/CDN default pages), Flan reports header checks as skipped.

DNS resolution behavior: Flan uses a deterministic resolver chain (custom resolver when provided, otherwise system resolver, then configured fallbacks) and records resolver/cache stats in scan metadata.

Cloudflare discovery behavior: Flan uses zones as the discovery boundary, keeps `A`, `AAAA`, and `CNAME` scan candidates, and skips validation, wildcard, and non-public-IP records by default.
When Cloudflare discovery is enabled, Flan can also persist a normalized inventory snapshot, compare it against a prior snapshot, and optionally narrow scans to added/changed hosts for scheduled delta workflows.

For GitHub Actions automation, set the repository secret `CLOUDFLARE_API_TOKEN`. If you do not want Cloudflare scope in plaintext repo settings, either pass zones/include/exclude as manual workflow inputs or store them in secrets named `CLOUDFLARE_ZONES`, `CLOUDFLARE_INCLUDE`, `CLOUDFLARE_EXCLUDE`, and `CLOUDFLARE_TOP_PORTS`.

Guardrails and DNS policy are configurable in `config/config.yaml`:

```yaml
scan:
  max_targets: 5000
  max_ports_per_target: 5000
  max_duration: 30m
dns:
  resolver: ""
  fallback_resolvers: ["1.1.1.1:53", "8.8.8.8:53"]
  lookup_timeout: 3s
cloudflare:
  enabled: false
  zones: []
  include: []
  exclude: []
  token_env: CLOUDFLARE_API_TOKEN
  timeout: 15s
  inventory_out: ""
  diff_against: ""
  delta_only: false
```

## Flags

| Flag | Description |
|------|-------------|
| `-t` | Target host/IP |
| `-l` | Target file (default `ips.txt`, `-` for stdin) |
| `-d` | Domain to enumerate via DNS |
| `-p` | Ports to scan |
| `--top-ports` | Use top port profile: `100`, `1000`, `2000`, or `5000` |
| `--subdomain-ports` | Domain mode port profile: `web`, `standard`, or `full` |
| `-c` | Config file (default `config/config.yaml`) |
| `-w` | Custom DNS subdomain wordlist |
| `-r` | Custom DNS resolver (ip:port) |
| `--cloudflare` | Discover scan targets from Cloudflare zone DNS records |
| `--cloudflare-zones` | Comma-separated Cloudflare zone filter |
| `--cloudflare-include` | Comma-separated hostname include filters |
| `--cloudflare-exclude` | Comma-separated hostname exclude filters |
| `--cloudflare-inventory-out` | Write normalized Cloudflare inventory snapshot to this path |
| `--cloudflare-diff-against` | Compare the current Cloudflare inventory against a previous snapshot |
| `--cloudflare-delta-only` | Scan only added/changed Cloudflare hosts when a previous snapshot is available |
| `--passive-only` | Skip brute-force, use passive sources only |
| `--subdomains-only` | Print discovered subdomains and exit (no port scan) |
| `--subfinder-sources` | Comma-separated passive sources override |
| `--subfinder-exclude-sources` | Comma-separated passive sources to exclude |
| `--subfinder-all` | Use all subfinder passive sources |
| `--subfinder-recursive` | Use only recursive-capable passive sources |
| `--subfinder-max-time` | Max passive enumeration time in minutes |
| `--subfinder-rate-limit` | Passive enumeration HTTP requests/second |
| `--subfinder-threads` | Passive enumeration threads |
| `--subfinder-provider-config` | Path to subfinder provider config |
| `--scan-cdn` | Scan all ports on CDN hosts (default: 80/443 only) |
| `--udp` | Enable UDP scanning (ports 53, 123, 161, 500 by default) |
| `--crawl` | Crawl HTTP/HTTPS services for endpoints, sensitive paths, and app fingerprinting |
| `--crawl-depth` | Max crawl depth (default: 2) |
| `--tls-enum` | Enumerate supported TLS versions and cipher suites (~60 connections per TLS port, off by default) |
| `--tls-verify` | Verify TLS certificates for TLS inspection, crawl, header probe, and TLS enumeration |
| `--context` | Asset context YAML file (auto-loads `config/context.yaml` if present) |
| `--analyze` | Detailed AI security analysis via Together API (requires `TOGETHER_API_KEY`) |
| `--json` | JSON output |
| `--jsonl` | JSONL streaming output |
| `--csv` | CSV output |

## Tests

```
go test ./... -v
```

## License

BSD 3-Clause License
