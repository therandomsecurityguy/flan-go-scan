![Go-Gopher-Flan-small](https://github.com/user-attachments/assets/e08ec4c5-8619-4437-a043-af7ea4a035fb)

# flan-go-scan

A modular, extensible network vulnerability scanner in Go. This is an update to the deprecated Flan Scan project: https://github.com/cloudflare/flan

## Features

- Scans TCP/UDP ports on multiple hosts
- Banner grabbing, TLS detection, protocol heuristics
- DNS resolution caching
- Rate limiting for API calls
- Scan resumption (checkpointing)
- Configurable via YAML
- Outputs JSON, CSV, or text reports

## Usage

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
  -ips=ips.txt \
  -format=json \
  -concurrency=500 \
  -vulners-api-key=$VULNERS_API_KEY
  ```
## Common Run Options

Specify a different IPs file:
`./flan-go-scan -ips=mytargets.txt`

Set port range:
`./flan-go-scan -start=20 -end=100`

Set timeout (milliseconds):
`./flan-go-scan -timeout=2000`

Set concurrency (number of parallel scans):
`./flan-go-scan -concurrency=200`

Output as JSON:
`./flan-go-scan -format=json > report.json`

Output as CSV:
`./flan-go-scan -format=csv > report.csv`

## License

BSD 3-Clause License
