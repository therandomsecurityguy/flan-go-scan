package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"

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

	ports, err := parsePorts(cfg.Scan.Ports)
	if err != nil {
		slog.Error("invalid port configuration", "err", err)
		os.Exit(1)
	}

	dnsCache := dns.NewDNSCache(cfg.DNS.TTL)
	limiter := scanner.NewRateLimiter(cfg.Scan.RateLimit)
	checkpoint := scanner.NewCheckpoint(cfg.Checkpoint.File)
	reportWriter := output.NewReportWriter(cfg.Output.Directory)

	pool := scanner.NewWorkerPool(cfg.Scan.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []scanner.ScanResult

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		ips, err := dnsCache.Lookup(host)
		if err != nil {
			slog.Warn("DNS lookup failed", "host", host, "err", err)
			continue
		}
		for _, ip := range ips {
			ipStr := ip.String()
			for _, port := range ports {
				if ctx.Err() != nil {
					break
				}
				if checkpoint.ShouldSkip(ipStr, port) {
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

					svc := scanner.DetectService(ip, port, cfg.Scan.Timeout)
					if svc.Name == "closed" {
						return
					}

					tlsResult := scanner.InspectTLS(ip, port, cfg.Scan.Timeout)
					mu.Lock()
					results = append(results, scanner.ScanResult{
						Host:    ip,
						Port:    port,
						Protocol: "tcp",
						Service: svc.Name,
						Version: svc.Version,
						Banner:  svc.Banner,
						TLS:     tlsResult,
					})
					mu.Unlock()
					checkpoint.Save(ip, port)
				}(ipStr, port)
			}
		}
	}
	wg.Wait()

	slog.Info("scan complete", "results", len(results))

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
