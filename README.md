![Go-Gopher-Flan-small](https://github.com/user-attachments/assets/e08ec4c5-8619-4437-a043-af7ea4a035fb)

# flan

A network scanner in Go. Successor to [Flan Scan](https://github.com/cloudflare/flan).

## Features

- TCP port scanning with bounded concurrency
- 51-protocol service fingerprinting via [fingerprintx](https://github.com/praetorian-inc/fingerprintx) (SSH, HTTP, MySQL, Redis, RDP, PostgreSQL, and more)
- Technology detection (Wappalyzer) and CPE generation
- TLS certificate inspection (version, cipher, subject, issuer, SANs, expiry, self-signed)
- CVE lookup by CPE via NVD API
- Host discovery (TCP probe to skip dead hosts)
- Passive subdomain enumeration via 9 no-key sources (crt.sh, Common Crawl, Wayback Machine, RapidDNS, Anubis, Digitorus, HudsonRock, SiteDossier, THC)
- CDN detection (Cloudflare) — limits scan to ports 80/443 by default on CDN hosts
- DNS enumeration with wildcard detection and custom wordlist/resolver support
- NS, MX, TXT, CNAME record lookups
- CIDR and stdin input support
- nmap top 100/1000 port lists
- Scan checkpointing and resumption
- Progress reporting
- UDP service detection (DNS, NTP, SNMP, IPSEC) via `--udp`
- Web crawler with app fingerprinting via `--crawl` (path, header, and cookie-based detection for 60+ CMSes, frameworks, and admin tools)
- Context-aware rate limiting and TLS inspection — clean shutdown on Ctrl+C
- Graceful shutdown on SIGINT/SIGTERM
- AI-powered security analysis via [Together API](https://together.ai) (DeepSeek V3.1) — brief summary on every scan, detailed report with `--analyze`
- Pretty streaming CLI output with TTY detection (JSONL when piping)
- JSON, JSONL (streaming), CSV, and text output
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

Scan all ports on CDN hosts (default is 80/443 only):

```
flan -d example.com --scan-cdn
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

## Flags

| Flag | Description |
|------|-------------|
| `-t` | Target host/IP |
| `-l` | Target file (default `ips.txt`, `-` for stdin) |
| `-d` | Domain to enumerate via DNS |
| `-p` | Ports to scan |
| `--top-ports` | Use nmap top port list: `100` or `1000` |
| `-c` | Config file (default `config/config.yaml`) |
| `-w` | Custom DNS subdomain wordlist |
| `-r` | Custom DNS resolver (ip:port) |
| `--passive-only` | Skip brute-force, use passive sources only |
| `--scan-cdn` | Scan all ports on CDN hosts (default: 80/443 only) |
| `--udp` | Enable UDP scanning (ports 53, 123, 161, 500 by default) |
| `--crawl` | Crawl HTTP/HTTPS services for endpoints, sensitive paths, and app fingerprinting |
| `--crawl-depth` | Max crawl depth (default: 2) |
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
