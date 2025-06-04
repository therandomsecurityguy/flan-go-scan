# flan-go-scan

A modular, extensible network vulnerability scanner in Go. The is an update to the deprecated Flan Scan project: https://github.com/cloudflare/flan

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
3. Build and run:

```
go build -o flan-go-scan ./cmd/flan-go-scan
./flan-go-scan -ips=ips.txt
```

## License

BSD 3-Clause License
