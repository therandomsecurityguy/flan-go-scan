![Go-Gopher-Flan-small](https://github.com/user-attachments/assets/e08ec4c5-8619-4437-a043-af7ea4a035fb)

# flan-go-scan

A modular, extensible network vulnerability scanner in Go. This is an update to the deprecated Flan Scan project: https://github.com/cloudflare/flan

## Features

- Scans TCP/UDP ports on multiple hosts
- Banner grabbing, TLS detection, protocol heuristics
- DNS enumeration (subdomain brute-forcing, zone transfer attempts)
- NS, MX, TXT, CNAME record lookups
- DNS resolution caching
- Rate limiting for API calls
- Scan resumption (checkpointing)
- Configurable via YAML
- Outputs JSON, CSV, or text reports

## Usage

### Domain-based scanning (recommended)

```
./flan-go-scan -domain=together.ai
```

This will:
1. Enumerate subdomains via DNS brute-forcing
2. Resolve NS, MX, TXT, CNAME records
3. Scan discovered hosts for open ports
4. Detect services and check for vulnerabilities

### Traditional IP-based scanning

1. Place targets in `ips.txt`
2. Edit `config/config.yaml` as needed
3. Build:

```
go build -o flan-go-scan ./cmd/flan-go-scan
```

4. Acquire API key from vulners.com and set environment variable:

```
export VULNERS_API_KEY="your_api_key_here"
```
5. Run with all of the features:

```
./flan-go-scan \
  -config=config/config.yaml \
  -ips=ips.txt
  ```
## Common Run Options

Scan a domain (DNS enumeration + port scan):
`./flan-go-scan -domain=example.com`

Specify a different IPs file:
`./flan-go-scan -ips=mytargets.txt`

Specify config file:
`./flan-go-scan -config=config/config.yaml`

## License

BSD 3-Clause License
