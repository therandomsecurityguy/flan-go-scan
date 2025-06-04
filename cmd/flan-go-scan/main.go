package main

import (
	"bufio"
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
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	var hosts []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			hosts = append(hosts, line)
		}
	}
	return hosts, scanner.Err()
}

func main() {
	configPath := flag.String("config", "config/config.yaml", "Path to config file")
	ipsFile := flag.String("ips", "ips.txt", "File with hosts to scan")
	flag.Parse()

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		fmt.Println("Config error:", err)
		os.Exit(1)
	}

	hosts, err := readHosts(*ipsFile)
	if err != nil {
		fmt.Println("Failed to read hosts:", err)
		os.Exit(1)
	}

	ports := parsePorts(cfg.Scan.Ports)
	dnsCache := dns.NewDNSCache(cfg.DNS.TTL)
	limiter := scanner.NewRateLimiter(cfg.Scan.RateLimit)
	checkpoint := scanner.NewCheckpoint(cfg.Checkpoint.File)
	reportWriter := output.NewReportWriter(cfg.Output.Directory)

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
				wg.Add(1)
				go func(ip string, port int) {
					defer wg.Done()
					limiter.Wait()
					open, banner := scanner.ScanTCP(ip, port, cfg.Scan.Timeout)
					if !open {
						return
					}
					tls := scanner.DetectTLS(ip, port, cfg.Scan.Timeout)
					service := scanner.DetectService(port, banner, tls)
					// For demo, fake vulnerability match
					vulns := []string{}
					if service == "ssh" {
						vulns = append(vulns, "CVE-2022-5678")
					}
					mu.Lock()
					results = append(results, scanner.ScanResult{
						Host: ip, Port: port, Protocol: "tcp", Service: service, Banner: banner, TLS: tls, Vulnerabilities: vulns,
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
			fmt.Printf("%s:%d [%s] TLS:%v - %s Vulns:%v\n", res.Host, res.Port, res.Service, res.TLS, res.Banner, res.Vulnerabilities)
		}
	}
}
