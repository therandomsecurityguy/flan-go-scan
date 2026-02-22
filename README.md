![Go-Gopher-Flan-small](https://github.com/user-attachments/assets/e08ec4c5-8619-4437-a043-af7ea4a035fb)

# flan-go-scan

A modular, extensible network vulnerability scanner in Go. This is an update to the deprecated Flan Scan project: https://github.com/cloudflare/flan

## Features

- TCP port scanning with bounded worker pool concurrency
- Service detection with version extraction (SSH, HTTP, SMTP, FTP, MySQL, Redis, RDP, and more)
- Banner grabbing and protocol heuristics
- TLS certificate inspection (version, cipher suite, subject, issuer, SANs, expiry, self-signed detection)
- DNS enumeration (subdomain brute-forcing, zone transfer attempts)
- NS, MX, TXT, CNAME record lookups
- DNS resolution caching
- CIDR input support and stdin piping (`-ips -`)
- Rate limiting
- Scan resumption (checkpointing)
- Graceful shutdown on SIGINT/SIGTERM
- Structured logging via `log/slog`
- Configurable via YAML
- Outputs JSON, JSONL (streaming), CSV, or text reports

## Usage

### Domain-based scanning (recommended)

```
./flan-go-scan -domain=together.ai
```

This will:
1. Enumerate subdomains via DNS brute-forcing
2. Resolve NS, MX, TXT, CNAME records
3. Scan discovered hosts for open ports
4. Detect services and extract versions

### IP-based scanning

1. Place targets in `ips.txt` (supports IPs, hostnames, CIDR notation)
2. Edit `config/config.yaml` as needed
3. Build:

```
go build -o flan-go-scan ./cmd/flan-go-scan
```

4. Run:

```
./flan-go-scan -config=config/config.yaml -ips=ips.txt
```

### Stdin piping

```
echo "10.0.0.0/24" | ./flan-go-scan -ips -
```

## Common Run Options

Scan a domain (DNS enumeration + port scan):
`./flan-go-scan -domain=example.com`

Specify a different IPs file:
`./flan-go-scan -ips=mytargets.txt`

Specify config file:
`./flan-go-scan -config=config/config.yaml`

## Tests

```
go test ./internal/scanner/ -v
```

## License

BSD 3-Clause License
