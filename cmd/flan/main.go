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

var version = "dev"

const banner = `
  __ _
 / _| | __ _ _ __    ___  ___ __ _ _ __
| |_| |/ _' | '_ \  / __|/ __/ _' | '_ \
|  _| | (_| | | | | \__ \ (_| (_| | | | |
|_| |_|\__,_|_| |_| |___/\___\__,_|_| |_| %s

`

func printBanner() {
	fmt.Fprintf(os.Stderr, "\033[36m"+banner+"\033[0m", version)
}

func usage() {
	fmt.Fprintf(os.Stderr, `Usage:
  flan [flags]

TARGET:
  -t, -target string       target host/IP to scan
  -l, -list string         file containing targets (default "ips.txt")
  -d, -domain string       domain to enumerate via DNS

PORTS:
  -p, -ports string        ports to scan (from config if not set)
  --top-ports string       use top port list: 100 or 1000

CONFIGURATION:
  -c, -config string       path to config file (default "config/config.yaml")
  -w, -wordlist string     custom DNS subdomain wordlist file
  -r, -resolver string     custom DNS resolver (ip:port)
  --passive-only           skip brute-force, use passive sources only
  --scan-cdn               scan all ports on CDN hosts (default: 80,443 only)
  --analyze                AI-powered analysis via Together API (requires TOGETHER_API_KEY)

OUTPUT:
  --json                   output in JSON format
  --jsonl                  output in JSONL format (streaming)
  --csv                    output in CSV format

EXAMPLES:
  flan -t scanme.nmap.org
  flan -l targets.txt --top-ports 1000
  flan -d together.ai
  echo "10.0.0.0/24" | flan -l -

`)
}

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
	flag.Usage = usage
	printBanner()

	configPath := flag.String("config", "config/config.yaml", "")
	configShort := flag.String("c", "config/config.yaml", "")
	listFile := flag.String("list", "ips.txt", "")
	listShort := flag.String("l", "ips.txt", "")
	target := flag.String("target", "", "")
	targetShort := flag.String("t", "", "")
	domain := flag.String("domain", "", "")
	domainShort := flag.String("d", "", "")
	portsFlag := flag.String("ports", "", "")
	portsShort := flag.String("p", "", "")
	topPorts := flag.String("top-ports", "", "")
	wordlist := flag.String("wordlist", "", "")
	wordlistShort := flag.String("w", "", "")
	resolver := flag.String("resolver", "", "")
	resolverShort := flag.String("r", "", "")
	passiveOnly := flag.Bool("passive-only", false, "")
	scanCDN := flag.Bool("scan-cdn", false, "")
	analyze := flag.Bool("analyze", false, "")
	jsonFlag := flag.Bool("json", false, "")
	jsonlFlag := flag.Bool("jsonl", false, "")
	csvFlag := flag.Bool("csv", false, "")
	flag.Parse()

	set := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { set[f.Name] = true })

	cfgPath := pick(set, "config", configPath, "c", configShort, "config/config.yaml")
	ipsFile := pick(set, "list", listFile, "l", listShort, "ips.txt")
	tgt := pick(set, "target", target, "t", targetShort, "")
	dom := pick(set, "domain", domain, "d", domainShort, "")
	portStr := pick(set, "ports", portsFlag, "p", portsShort, "")
	wl := pick(set, "wordlist", wordlist, "w", wordlistShort, "")
	res := pick(set, "resolver", resolver, "r", resolverShort, "")

	cfg, err := config.LoadConfig(cfgPath)
	if err != nil {
		slog.Error("config error", "err", err)
		os.Exit(1)
	}

	if *passiveOnly && dom == "" {
		slog.Warn("--passive-only has no effect without -d")
	}

	if *jsonFlag {
		cfg.Output.Format = "json"
	}
	if *jsonlFlag {
		cfg.Output.Format = "jsonl"
	}
	if *csvFlag {
		cfg.Output.Format = "csv"
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

	if tgt != "" {
		hosts = append(hosts, tgt)
	} else if dom != "" {
		slog.Info("enumerating subdomains", "domain", dom)

		slog.Info("running passive enumeration")
		passiveHosts, err := dns.PassiveEnumerate(ctx, dom, cfg.Scan.Timeout)
		if err != nil {
			slog.Warn("passive enumeration failed", "err", err)
		} else {
			slog.Info("passive enumeration complete", "subdomains", len(passiveHosts))
		}
		for _, h := range passiveHosts {
			hosts = append(hosts, h)
		}

		if !*passiveOnly {
			slog.Info("running brute-force enumeration")
			var enumerator *dns.Enumerator
			if res != "" {
				enumerator = dns.NewEnumeratorWithResolver(cfg.Scan.Timeout, 50, res)
			} else {
				enumerator = dns.NewEnumerator(cfg.Scan.Timeout, 50)
			}

			var enumResults []dns.EnumerationResult
			if wl != "" {
				words, err := dns.LoadWordlist(wl)
				if err != nil {
					slog.Error("failed to load wordlist", "err", err)
					os.Exit(1)
				}
				enumResults, err = enumerator.EnumerateWithWordlist(dom, words)
			} else {
				enumResults, err = enumerator.Enumerate(dom)
			}
			if err != nil {
				slog.Warn("brute-force enumeration failed", "err", err)
			}

			for _, result := range enumResults {
				hosts = append(hosts, result.IP.String())
			}
			slog.Info("brute-force enumeration complete", "hosts", len(enumResults))
		}

		seen := make(map[string]bool)
		var deduped []string
		for _, h := range hosts {
			if !seen[h] {
				seen[h] = true
				deduped = append(deduped, h)
			}
		}
		hosts = deduped
		slog.Info("subdomain enumeration complete", "unique_hosts", len(hosts))

		nsRecords, err := dns.GetNSRecords(dom)
		if err == nil && len(nsRecords) > 0 {
			slog.Info("nameservers", "records", nsRecords)
		}

		mxRecords, err := dns.GetMXRecords(dom)
		if err == nil && len(mxRecords) > 0 {
			slog.Info("mail servers", "records", mxRecords)
		}

		txtRecords, err := dns.GetTXTRecords(dom)
		if err == nil && len(txtRecords) > 0 {
			slog.Info("TXT records", "records", txtRecords)
		}
	} else {
		hosts, err = readHosts(ipsFile)
		if err != nil {
			slog.Error("failed to read hosts", "err", err)
			os.Exit(1)
		}
	}

	if len(hosts) == 0 {
		slog.Error("no hosts to scan, provide -t, -d, or -l")
		os.Exit(1)
	}

	var ports []int
	switch *topPorts {
	case "100":
		ports = scanner.TopPorts100
	case "1000":
		ports = scanner.TopPorts1000
	case "":
		if portStr != "" {
			ports, err = parsePorts(portStr)
		} else {
			ports, err = parsePorts(cfg.Scan.Ports)
		}
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
	reportWriter, err := output.NewReportWriter(cfg.Output.Directory)
	if err != nil {
		slog.Error("failed to create report writer", "err", err)
		os.Exit(1)
	}
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
		type aliveResult struct {
			ip    string
			alive bool
		}
		results := make(chan aliveResult, len(allIPs))
		discoveryPool := scanner.NewWorkerPool(cfg.Scan.Workers)
		var discoveryWg sync.WaitGroup
		for _, ip := range allIPs {
			discoveryPool.Acquire()
			discoveryWg.Add(1)
			go func(ip string) {
				defer discoveryWg.Done()
				defer discoveryPool.Release()
				results <- aliveResult{ip: ip, alive: scanner.IsHostAlive(ip, cfg.Scan.Timeout)}
			}(ip)
		}
		discoveryWg.Wait()
		close(results)
		var alive []string
		for r := range results {
			if r.alive {
				alive = append(alive, r.ip)
			}
		}
		slog.Info("host discovery complete", "alive", len(alive), "filtered", len(allIPs)-len(alive))
		allIPs = alive
	}

	if len(allIPs) == 0 {
		slog.Info("no live hosts found")
		os.Exit(0)
	}

	cdnDetector := scanner.NewCDNDetector()
	cdnHosts := make(map[string]string)
	for _, ip := range allIPs {
		if cdn := cdnDetector.Detect(ip); cdn != "" {
			cdnHosts[ip] = cdn
		}
	}
	if len(cdnHosts) > 0 {
		slog.Info("CDN hosts detected", "count", len(cdnHosts))
	}

	progress := scanner.NewProgress(len(allIPs))
	statsInterval := 5
	if cfg.Scan.StatsInterval > 0 {
		statsInterval = cfg.Scan.StatsInterval
	}
	progressCtx, stopProgress := context.WithCancel(ctx)
	go progress.Run(progressCtx, time.Duration(statsInterval)*time.Second)

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
			}
			if jsonlWriter == nil || *analyze {
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
		cdn := cdnHosts[ip]
		for _, port := range ports {
			if ctx.Err() != nil {
				break
			}
			if cdn != "" && !*scanCDN && port != 80 && port != 443 {
				continue
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
					if fp.Metadata != nil {
						var meta struct {
							CPEs []string `json:"cpes"`
						}
						if json.Unmarshal(fp.Metadata, &meta) == nil {
							for _, cpe := range meta.CPEs {
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
						CDN:             cdn,
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
					CDN:      cdn,
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

	if ctx.Err() == nil {
		checkpoint.Clear()
	}

	stopProgress()

	slog.Info("scan complete",
		"services_found", progress.ServicesFound.Load(),
		"ports_scanned", progress.PortsScanned.Load(),
	)

	if *analyze && len(results) > 0 {
		analysis, err := scanner.Analyze(ctx, results, cfg.Output.Directory)
		if err != nil {
			slog.Error("analysis failed", "err", err)
		} else {
			fmt.Println()
			printAnalysis(analysis.Analysis)
			fmt.Println("\033[2m  Powered by Together AI (deepseek-ai/DeepSeek-V3.1)\033[0m")
			fmt.Println()
		}
	}

	if jsonlWriter != nil {
		if jsonlWriter.Filename != "" {
			slog.Info("report written", "path", jsonlWriter.Filename)
		}
		return
	}

	switch cfg.Output.Format {
	case "json":
		if err := reportWriter.WriteJSON(results); err != nil {
			slog.Error("failed to write JSON report", "err", err)
		} else {
			slog.Info("report written", "format", "json", "directory", cfg.Output.Directory)
		}
	case "csv":
		if err := reportWriter.WriteCSV(results); err != nil {
			slog.Error("failed to write CSV report", "err", err)
		} else {
			slog.Info("report written", "format", "csv", "directory", cfg.Output.Directory)
		}
	default:
		for _, res := range results {
			fmt.Printf("%s:%d [%s %s] TLS:%v %s\n", res.Host, res.Port, res.Service, res.Version, res.TLS != nil, res.Banner)
		}
	}
}

func printAnalysis(text string) {
	const (
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
		cyan   = "\033[36m"
		bold   = "\033[1m"
		dim    = "\033[2m"
		reset  = "\033[0m"
	)

	for _, line := range strings.Split(text, "\n") {
		clean := strings.ReplaceAll(line, "**", "")
		clean = strings.TrimLeft(clean, "# ")
		clean = strings.TrimSpace(clean)
		if clean == "" {
			fmt.Println()
			continue
		}

		switch {
		case strings.Contains(clean, "CRITICAL"):
			fmt.Println(bold + red + clean + reset)
		case strings.Contains(clean, "HIGH"):
			fmt.Println(red + clean + reset)
		case strings.Contains(clean, "MEDIUM"):
			fmt.Println(yellow + clean + reset)
		case strings.Contains(clean, "LOW"):
			fmt.Println(green + clean + reset)
		case strings.Contains(clean, "INFO"):
			fmt.Println(green + clean + reset)
		case strings.HasPrefix(line, "---"):
			fmt.Println(dim + "─────────────────────────────────────────" + reset)
		case strings.HasPrefix(clean, "- "):
			fmt.Println(dim + "  " + clean + reset)
		default:
			fmt.Println(clean)
		}
	}
}

func pick(set map[string]bool, long string, longVal *string, short string, shortVal *string, def string) string {
	if set[long] {
		return *longVal
	}
	if set[short] {
		return *shortVal
	}
	return def
}
