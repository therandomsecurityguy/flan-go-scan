package main

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/therandomsecurityguy/flan-go-scan/internal/config"
	"github.com/therandomsecurityguy/flan-go-scan/internal/dns"
	"github.com/therandomsecurityguy/flan-go-scan/internal/output"
	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func parsePorts(portStr string) []int {
	var ports []int
	for _, part := range strings.Split(portStr, ",") {
		if strings.Contains(part, "-") {
			bounds := strings.Split(part, "-")
			start, _ := strconv.Atoi(bounds[0])
			end, _ := strconv.Atoi(bounds[1])
			for p := start; p <= end; p++ {
				ports = append(ports, p)
			}
		} else {
			p, _ := strconv.Atoi(part)
			ports = append(ports, p)
		}
	}
	return ports
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
		fmt.Println("Config error:", err)
		os.Exit(1)
	}

	var hosts []string

	if *domain != "" {
		fmt.Printf("Enumerating DNS records for domain: %s\n", *domain)
		enumerator := dns.NewEnumerator(cfg.Scan.Timeout, 50)
		enumResults, err := enumerator.Enumerate(*domain)
		if err != nil {
			fmt.Printf("DNS enumeration error: %v\n", err)
			os.Exit(1)
		}

		fmt.Printf("Found %d hosts via DNS enumeration\n", len(enumResults))
		for _, result := range enumResults {
			hostIP := result.IP.String()
			fmt.Printf("  - %s (%s) [%s]\n", result.Hostname, hostIP, result.Type)
			hosts = append(hosts, hostIP)
		}

		nsRecords, err := dns.GetNSRecords(*domain)
		if err == nil && len(nsRecords) > 0 {
			fmt.Printf("Nameservers: %v\n", nsRecords)
		}

		mxRecords, err := dns.GetMXRecords(*domain)
		if err == nil && len(mxRecords) > 0 {
			fmt.Printf("Mail servers: %v\n", mxRecords)
		}

		txtRecords, err := dns.GetTXTRecords(*domain)
		if err == nil && len(txtRecords) > 0 {
			fmt.Printf("TXT records: %v\n", txtRecords)
		}
	} else {
		hosts, err = readHosts(*ipsFile)
		if err != nil {
			fmt.Println("Failed to read hosts:", err)
			os.Exit(1)
		}
	}

	if len(hosts) == 0 {
		fmt.Println("No hosts to scan. Provide -domain or hosts file.")
		os.Exit(1)
	}

	ports := parsePorts(cfg.Scan.Ports)
	dnsCache := dns.NewDNSCache(cfg.DNS.TTL)
	limiter := scanner.NewRateLimiter(cfg.Scan.RateLimit)
	checkpoint := scanner.NewCheckpoint(cfg.Checkpoint.File)
	reportWriter := output.NewReportWriter(cfg.Output.Directory)

	pool := scanner.NewWorkerPool(cfg.Scan.Workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var results []scanner.ScanResult

	for _, host := range hosts {
		ips, err := dnsCache.Lookup(host)
		if err != nil {
			fmt.Printf("DNS error for %s: %v\n", host, err)
			continue
		}
		for _, ip := range ips {
			ipStr := ip.String()
			for _, port := range ports {
				if checkpoint.ShouldSkip(ipStr, port) {
					continue
				}
				pool.Acquire()
				wg.Add(1)
				go func(ip string, port int) {
					defer wg.Done()
					defer pool.Release()
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

	// Output
	switch cfg.Output.Format {
	case "json":
		reportWriter.WriteJSON(results)
	case "csv":
		reportWriter.WriteCSV(results)
	default:
		for _, res := range results {
			fmt.Printf("%s:%d [%s %s] TLS:%v %s\n", res.Host, res.Port, res.Service, res.Version, res.TLS != nil, res.Banner)
		}
	}
}
