package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/config"
	"github.com/therandomsecurityguy/flan-go-scan/internal/dns"
	"github.com/therandomsecurityguy/flan-go-scan/internal/output"
	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func parsePorts(portStr string) ([]int, error) {
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("invalid port range start %q: %w", bounds[0], err)
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("invalid port range end %q: %w", bounds[1], err)
			}
			if start > end || start < 1 || end > 65535 {
				return nil, fmt.Errorf("invalid port range %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", part, err)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			ports = append(ports, p)
		}
	}
	return ports, nil
}

func readHosts(filename string) ([]string, error) {
	var r *os.File
	if filename == "-" {
		r = os.Stdin
	} else {
		f, err := os.Open(filename)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		r = f
	}
	return scanner.ParseTargets(r)
}

func main() {
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	ipsFile := flag.String("ips", "ips.txt", "File with hosts to scan")
	domain := flag.String("domain", "", "Domain to enumerate (e.g., together.ai)")
	topPorts := flag.String("top-ports", "", "Use top port list: 100 or 1000")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Warn("received signal, shutting down", "signal", sig)
		cancel()
	}()

	var hosts []string

	if *domain != "" {
		slog.Info("enumerating DNS records", "domain", *domain)
		enumerator := dns.NewEnumerator(cfg.Scan.Timeout, 50)
		enumResults, err := enumerator.Enumerate(*domain)
		if err != nil {
			slog.Error("DNS enumeration failed", "err", err)
			os.Exit(1)
		}

		slog.Info("DNS enumeration complete", "hosts", len(enumResults))
		for _, result := range enumResults {
			hostIP := result.IP.String()
			slog.Info("discovered host", "hostname", result.Hostname, "ip", hostIP, "type", result.Type)
			hosts = append(hosts, hostIP)
		}

		nsRecords, err := dns.GetNSRecords(*domain)
		if err == nil && len(nsRecords) > 0 {
			slog.Info("nameservers", "records", nsRecords)
		}

		mxRecords, err := dns.GetMXRecords(*domain)
		if err == nil && len(mxRecords) > 0 {
			slog.Info("mail servers", "records", mxRecords)
		}

		txtRecords, err := dns.GetTXTRecords(*domain)
		if err == nil && len(txtRecords) > 0 {
			slog.Info("TXT records", "records", txtRecords)
		}
	} else {
		hosts, err = readHosts(*ipsFile)
		if err != nil {
			slog.Error("failed to read hosts", "err", err)
			os.Exit(1)
		}
	}

	if len(hosts) == 0 {
		slog.Error("no hosts to scan, provide -domain or hosts file")
		os.Exit(1)
	}

	var ports []int
	switch *topPorts {
	case "100":
		ports = scanner.TopPorts100
	case "1000":
		ports = scanner.TopPorts1000
	case "":
		var err error
		ports, err = parsePorts(cfg.Scan.Ports)
		if err != nil {
			slog.Error("invalid port configuration", "err", err)
			os.Exit(1)
		}
	default:
		slog.Error("invalid --top-ports value, use 100 or 1000", "value", *topPorts)
		os.Exit(1)
	}

	dnsCache := dns.NewDNSCache(cfg.DNS.TTL)
	limiter := scanner.NewRateLimiter(cfg.Scan.RateLimit)
	checkpoint := scanner.NewCheckpoint(cfg.Checkpoint.File)
	reportWriter := output.NewReportWriter(cfg.Output.Directory)
	cveLookup := scanner.NewCVELookup()

	var jsonlWriter *output.JSONLWriter
	if cfg.Output.Format == "jsonl" {
		jw, err := output.NewJSONLWriter(cfg.Output.Directory)
		if err != nil {
			slog.Error("failed to create JSONL writer", "err", err)
			os.Exit(1)
		}
		jsonlWriter = jw
		defer jsonlWriter.Close()
	}

	var allIPs []string
	for _, host := range hosts {
		ips, err := dnsCache.Lookup(host)
		if err != nil {
			slog.Warn("DNS lookup failed", "host", host, "err", err)
			continue
		}
		for _, ip := range ips {
			allIPs = append(allIPs, ip.String())
		}
	}

	if cfg.Scan.Discovery {
		slog.Info("running host discovery", "targets", len(allIPs))
		var alive []string
		for _, ip := range allIPs {
			if scanner.IsHostAlive(ip, cfg.Scan.Timeout) {
				alive = append(alive, ip)
			}
		}
		slog.Info("host discovery complete", "alive", len(alive), "filtered", len(allIPs)-len(alive))
		allIPs = alive
	}

	if len(allIPs) == 0 {
		slog.Info("no live hosts found")
		os.Exit(0)
	}

	progress := scanner.NewProgress(len(allIPs))
	statsInterval := 5
	if cfg.Scan.StatsInterval > 0 {
		statsInterval = cfg.Scan.StatsInterval
	}
	go progress.Run(ctx, time.Duration(statsInterval)*time.Second)

	resultsCh := make(chan scanner.ScanResult, 100)
	var collectWg sync.WaitGroup
	var results []scanner.ScanResult

	collectWg.Add(1)
	go func() {
		defer collectWg.Done()
		for res := range resultsCh {
			if jsonlWriter != nil {
				if err := jsonlWriter.WriteResult(res); err != nil {
					slog.Error("failed to write JSONL result", "err", err)
				}
			} else {
				results = append(results, res)
			}
		}
	}()

	pool := scanner.NewWorkerPool(cfg.Scan.Workers)
	var wg sync.WaitGroup

	for _, ip := range allIPs {
		if ctx.Err() != nil {
			break
		}
		for _, port := range ports {
			if ctx.Err() != nil {
				break
			}
			if checkpoint.ShouldSkip(ip, port) {
				continue
			}
			pool.Acquire()
			wg.Add(1)
			go func(ip string, port int) {
				defer wg.Done()
				defer pool.Release()
				if ctx.Err() != nil {
					return
				}
				limiter.Wait()
				progress.PortsScanned.Add(1)

				fp := scanner.Fingerprint(ip, port, cfg.Scan.Timeout)
				if fp != nil {
					progress.ServicesFound.Add(1)
					var tlsResult *scanner.TLSResult
					if fp.TLS {
						tlsResult = scanner.InspectTLS(ip, port, cfg.Scan.Timeout)
					}

					var vulns []string
					var cpes []string
					if fp.Metadata != nil {
						var meta struct {
							CPEs []string `json:"cpes"`
						}
						if json.Unmarshal(fp.Metadata, &meta) == nil {
							cpes = meta.CPEs
							for _, cpe := range cpes {
								for _, cve := range cveLookup.Lookup(cpe) {
									vulns = append(vulns, cve.ID)
								}
							}
						}
					}

					resultsCh <- scanner.ScanResult{
						Host:            ip,
						Port:            port,
						Protocol:        fp.Transport,
						Service:         fp.Service,
						Version:         fp.Version,
						TLS:             tlsResult,
						Metadata:        fp.Metadata,
						Vulnerabilities: vulns,
					}
					checkpoint.Save(ip, port)
					return
				}

				svc := scanner.DetectService(ip, port, cfg.Scan.Timeout)
				if svc.Name == "closed" {
					return
				}

				progress.ServicesFound.Add(1)
				tlsResult := scanner.InspectTLS(ip, port, cfg.Scan.Timeout)
				resultsCh <- scanner.ScanResult{
					Host:     ip,
					Port:     port,
					Protocol: "tcp",
					Service:  svc.Name,
					Version:  svc.Version,
					Banner:   svc.Banner,
					TLS:      tlsResult,
				}
				checkpoint.Save(ip, port)
			}(ip, port)
		}
		progress.HostsDone.Add(1)
	}
	wg.Wait()
	close(resultsCh)
	collectWg.Wait()

	if err := checkpoint.Flush(); err != nil {
		slog.Error("failed to flush checkpoint", "err", err)
	}

	slog.Info("scan complete",
		"services_found", progress.ServicesFound.Load(),
		"ports_scanned", progress.PortsScanned.Load(),
	)

	if jsonlWriter != nil {
		return
	}

	switch cfg.Output.Format {
	case "json":
		if err := reportWriter.WriteJSON(results); err != nil {
			slog.Error("failed to write JSON report", "err", err)
		}
	case "csv":
		if err := reportWriter.WriteCSV(results); err != nil {
			slog.Error("failed to write CSV report", "err", err)
		}
	default:
		for _, res := range results {
			fmt.Printf("%s:%d [%s %s] TLS:%v %s\n", res.Host, res.Port, res.Service, res.Version, res.TLS != nil, res.Banner)
		}
	}
}
