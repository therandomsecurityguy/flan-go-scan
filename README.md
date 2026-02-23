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
- Graceful shutdown on SIGINT/SIGTERM
- JSON, JSONL (streaming), CSV, and text output
- Configurable via YAML

## Build

```
go build -o flan ./cmd/flan
```

## Usage

```
./flan --help
```

Scan a single target:

```
./flan -t scanme.nmap.org
```

Scan a domain (DNS enumeration + port scan):

```
./flan -d example.com
```

Scan from a file with top 1000 ports:

```
./flan -l targets.txt --top-ports 1000
```

Scan a CIDR range from stdin:

```
echo "10.0.0.0/24" | ./flan -l -
```

Scan with custom wordlist and resolver:

```
./flan -d example.com -w wordlist.txt -r 8.8.8.8:53
```

Passive enumeration only (skip brute-force):

```
./flan -d example.com --passive-only
```

Scan all ports on CDN hosts (default is 80/443 only):

```
./flan -d example.com --scan-cdn
```

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
| `--json` | JSON output |
| `--jsonl` | JSONL streaming output |
| `--csv` | CSV output |

## Tests

```
go test ./... -v
```

## License

BSD 3-Clause License
