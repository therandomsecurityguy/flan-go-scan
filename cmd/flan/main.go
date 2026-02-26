package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"net"
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
  --udp                    enable UDP scanning (ports 53,123,161,500 by default)
  --crawl                  crawl HTTP/HTTPS services for endpoints and sensitive paths
  --crawl-depth int        max crawl depth (default: 2)
  --tls-enum               enumerate supported TLS versions and cipher suites (~60 connections per TLS port)
  --asn                    look up ASN and organization for each host via Cymru DNS
  --context string         YAML file with asset context and policies for AI analysis
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
	udpFlag := flag.Bool("udp", false, "")
	crawlFlag := flag.Bool("crawl", false, "")
	crawlDepth := flag.Int("crawl-depth", 0, "")
	tlsEnumFlag := flag.Bool("tls-enum", false, "")
	asnFlag := flag.Bool("asn", false, "")
	contextFile := flag.String("context", "", "")
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

	if set["crawl-depth"] && *crawlDepth > 0 {
		cfg.Scan.CrawlDepth = *crawlDepth
	}

	var scanCtx *scanner.ScanContext
	ctxPath := *contextFile
	if ctxPath == "" {
		ctxPath = "config/context.yaml"
	}
	if sc, err := scanner.LoadContext(ctxPath); err == nil {
		scanCtx = sc
	} else if *contextFile != "" {
		slog.Error("failed to load context file", "err", err)
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

	fi, _ := os.Stdout.Stat()
	isTTY := (fi.Mode() & os.ModeCharDevice) != 0
	prettyMode := isTTY && !*jsonFlag && !*jsonlFlag && !*csvFlag
	if prettyMode {
		if cfg.Output.Directory == "-" {
			cfg.Output.Directory = "reports"
		}
		cfg.Output.Format = "jsonl"
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
				enumResults, err = enumerator.EnumerateWithWordlist(ctx, dom, words)
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
	checkpoint, err := scanner.NewCheckpoint(cfg.Checkpoint.File)
	if err != nil {
		slog.Error("invalid checkpoint path", "err", err)
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

	hostnameFor := make(map[string]string)
	asnFor := make(map[string]string)
	orgFor := make(map[string]string)
	ptrFor := make(map[string]string)
	var allIPs []string
	for _, host := range hosts {
		ips, err := dnsCache.Lookup(host)
		if err != nil {
			slog.Warn("DNS lookup failed", "host", host, "err", err)
			continue
		}
		for _, ip := range ips {
			s := ip.String()
			allIPs = append(allIPs, s)
			if net.ParseIP(host) == nil {
				hostnameFor[s] = host
			}
			if *asnFlag {
				asn, org := scanner.LookupASN(ctx, s, cfg.Scan.Timeout)
				if asn != "" {
					asnFor[s] = asn
					orgFor[s] = org
				}
				if ptrs := scanner.LookupPTR(s); len(ptrs) > 0 {
					ptrFor[s] = ptrs[0]
				}
			}
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
	if !prettyMode {
		go progress.Run(progressCtx, time.Duration(statsInterval)*time.Second)
	}

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
			if prettyMode {
				printResult(res)
			}
			if jsonlWriter == nil || *analyze || prettyMode {
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
				if err := limiter.Wait(ctx); err != nil {
					return
				}
				progress.PortsScanned.Add(1)

				fp := scanner.Fingerprint(ip, port, cfg.Scan.Timeout)
				if fp != nil {
					progress.ServicesFound.Add(1)
					var tlsResult *scanner.TLSResult
					if fp.TLS {
						tlsResult = scanner.InspectTLS(ctx, ip, port, cfg.Scan.Timeout)
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

					var endpoints []scanner.CrawlResult
					var appFP *scanner.AppFingerprint
					if *crawlFlag && scanner.IsHTTPService(fp.Service, port, fp.TLS) {
						endpoints, appFP = scanner.Crawl(ctx, scanner.HTTPScheme(fp.TLS), ip, port, cfg.Scan.CrawlDepth, cfg.Scan.Timeout, 100*time.Millisecond)
					}

					var secHeaders []scanner.HeaderFinding
					if scanner.IsHTTPService(fp.Service, port, fp.TLS) {
						isTLS := fp.TLS || port == 443 || port == 8443 || port == 4443
						secHeaders = scanner.InspectHeaders(ctx, scanner.HTTPScheme(isTLS), ip, hostnameFor[ip], port, cfg.Scan.Timeout)
					}

					var tlsEnum *scanner.TLSEnum
					if *tlsEnumFlag && (fp.TLS || port == 443 || port == 8443 || port == 4443) {
						tlsEnum = scanner.EnumerateTLS(ctx, ip, hostnameFor[ip], port, cfg.Scan.Timeout)
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
						Endpoints:       endpoints,
						App:             appFP,
						SecurityHeaders: secHeaders,
						TLSEnum:         tlsEnum,
						Hostname:        ptrFor[ip],
						ASN:             asnFor[ip],
						Org:             orgFor[ip],
					}
					checkpoint.Save(ip, port)
					return
				}

				svc := scanner.DetectService(ip, port, cfg.Scan.Timeout)
				if svc.Name == "closed" {
					return
				}

				progress.ServicesFound.Add(1)
				tlsResult := scanner.InspectTLS(ctx, ip, port, cfg.Scan.Timeout)

				var endpoints []scanner.CrawlResult
				var appFP *scanner.AppFingerprint
				hasTLS := tlsResult != nil || port == 443 || port == 8443 || port == 4443
				if *crawlFlag && scanner.IsHTTPService(svc.Name, port, tlsResult != nil) {
					endpoints, appFP = scanner.Crawl(ctx, scanner.HTTPScheme(hasTLS), ip, port, cfg.Scan.CrawlDepth, cfg.Scan.Timeout, 100*time.Millisecond)
				}

				var secHeaders []scanner.HeaderFinding
				if scanner.IsHTTPService(svc.Name, port, tlsResult != nil) {
					secHeaders = scanner.InspectHeaders(ctx, scanner.HTTPScheme(hasTLS), ip, hostnameFor[ip], port, cfg.Scan.Timeout)
				}

				var tlsEnum *scanner.TLSEnum
				if *tlsEnumFlag && hasTLS {
					tlsEnum = scanner.EnumerateTLS(ctx, ip, hostnameFor[ip], port, cfg.Scan.Timeout)
				}

				resultsCh <- scanner.ScanResult{
					Host:            ip,
					Port:            port,
					Protocol:        "tcp",
					Service:         svc.Name,
					Version:         svc.Version,
					Banner:          svc.Banner,
					CDN:             cdn,
					TLS:             tlsResult,
					Endpoints:       endpoints,
					App:             appFP,
					SecurityHeaders: secHeaders,
					TLSEnum:         tlsEnum,
					Hostname:        ptrFor[ip],
					ASN:             asnFor[ip],
					Org:             orgFor[ip],
				}
				checkpoint.Save(ip, port)
			}(ip, port)
		}
		progress.HostsDone.Add(1)
	}
	wg.Wait()

	udpEnabled := *udpFlag || cfg.Scan.UDP
	if udpEnabled {
		udpPortStr := cfg.Scan.UDPPorts
		udpPorts, err := parsePorts(udpPortStr)
		if err != nil {
			slog.Error("invalid UDP port configuration", "err", err)
			os.Exit(1)
		}
		var udpWg sync.WaitGroup
		for _, ip := range allIPs {
			if ctx.Err() != nil {
				break
			}
			for _, port := range udpPorts {
				if ctx.Err() != nil {
					break
				}
				pool.Acquire()
				udpWg.Add(1)
				go func(ip string, port int) {
					defer udpWg.Done()
					defer pool.Release()
					if ctx.Err() != nil {
						return
					}
					if err := limiter.Wait(ctx); err != nil {
						return
					}
					fp := scanner.FingerprintUDP(ip, port, cfg.Scan.Timeout)
					if fp == nil {
						return
					}
					progress.ServicesFound.Add(1)
					resultsCh <- scanner.ScanResult{
						Host:     ip,
						Port:     port,
						Protocol: "udp",
						Service:  fp.Service,
						Version:  fp.Version,
						Metadata: fp.Metadata,
					}
				}(ip, port)
			}
		}
		udpWg.Wait()
	}

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

	if scanCtx != nil && len(results) > 0 {
		violations := scanner.CheckPolicies(results, scanCtx)
		if prettyMode {
			fmt.Println()
			if len(violations) > 0 {
				fmt.Printf("\033[2m  ──────────────\033[0m \033[1m\033[31mPolicy Violations\033[0m \033[2m──────────────\033[0m\n\n")
				for _, v := range violations {
					color := "\033[33m"
					if v.Severity == "CRITICAL" {
						color = "\033[1m\033[31m"
					} else if v.Severity == "HIGH" {
						color = "\033[31m"
					}
					loc := v.Host
					if v.Port > 0 {
						loc = fmt.Sprintf("%s:%d", v.Host, v.Port)
					}
					fmt.Printf("  %s[%s]%s  %s  %s\n", color, v.Severity, "\033[0m", loc, v.Detail)
				}
			} else {
				fmt.Printf("  \033[32m✓\033[0m  all policies satisfied\n")
			}
			fmt.Println()
		}
	}

	if prettyMode && !*analyze && os.Getenv("TOGETHER_API_KEY") != "" && len(results) > 0 {
		fmt.Print("\033[2m  Analyzing...\033[0m\r")
		brief, err := scanner.AnalyzeBrief(ctx, results, scanCtx)
		fmt.Print("                \r")
		if err == nil {
			fmt.Println()
			fmt.Printf("\033[2m  ──────────────\033[0m \033[1m\033[36mAI Analysis\033[0m \033[2m──────────────\033[0m\n\n")
			printAnalysis(brief)
			fmt.Println("\033[2m  Powered by Together AI (deepseek-ai/DeepSeek-V3.1)\033[0m")
			fmt.Println()
		}
	}

	if *analyze && len(results) > 0 {
		analysis, err := scanner.Analyze(ctx, results, cfg.Output.Directory, scanCtx)
		if err != nil {
			slog.Error("analysis failed", "err", err)
		} else {
			fmt.Println()
			fmt.Printf("\033[2m  ──────────────\033[0m \033[1m\033[36mAI Analysis\033[0m \033[2m──────────────\033[0m\n\n")
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
	case "json", "csv":
		rw, err := output.NewReportWriter(cfg.Output.Directory)
		if err != nil {
			slog.Error("failed to create report writer", "err", err)
			os.Exit(1)
		}
		if cfg.Output.Format == "json" {
			if err := rw.WriteJSON(results); err != nil {
				slog.Error("failed to write JSON report", "err", err)
			} else {
				slog.Info("report written", "format", "json", "directory", cfg.Output.Directory)
			}
		} else {
			if err := rw.WriteCSV(results); err != nil {
				slog.Error("failed to write CSV report", "err", err)
			} else {
				slog.Info("report written", "format", "csv", "directory", cfg.Output.Directory)
			}
		}
	default:
		for _, res := range results {
			fmt.Printf("%s:%d [%s %s] TLS:%v %s\n", res.Host, res.Port, res.Service, res.Version, res.TLS != nil, res.Banner)
		}
	}
}

func printResult(res scanner.ScanResult) {
	const (
		bold   = "\033[1m"
		dim    = "\033[2m"
		red    = "\033[31m"
		yellow = "\033[33m"
		green  = "\033[32m"
		cyan   = "\033[36m"
		reset  = "\033[0m"
	)

	tls := ""
	if res.TLS != nil {
		tls = dim + "  " + res.TLS.Version + reset
		if res.TLS.Expired {
			tls += red + " (expired)" + reset
		}
	}

	version := ""
	if res.Version != "" {
		version = "  " + res.Version
	}

	fmt.Printf("%s%-21s%s  %s%-10s%s%s%s\n",
		bold+cyan, fmt.Sprintf("%s:%d", res.Host, res.Port), reset,
		cyan, res.Service, reset,
		version, tls,
	)

	if res.Hostname != "" || res.ASN != "" {
		var meta []string
		if res.Hostname != "" {
			meta = append(meta, res.Hostname)
		}
		if res.ASN != "" {
			label := "AS" + res.ASN
			if res.Org != "" {
				label += " " + res.Org
			}
			meta = append(meta, label)
		}
		fmt.Printf("  %sasn%s  %s\n", cyan, reset, strings.Join(meta, "  ·  "))
	}

	if res.App != nil {
		var parts []string
		if res.App.Server != "" {
			parts = append(parts, res.App.Server)
		}
		if res.App.PoweredBy != "" {
			parts = append(parts, res.App.PoweredBy)
		}
		if res.App.Generator != "" {
			parts = append(parts, res.App.Generator)
		}
		if len(res.App.Apps) > 0 {
			parts = append(parts, strings.Join(res.App.Apps, ", "))
		}
		if len(parts) > 0 {
			fmt.Printf("  %sapp%s  %s\n", cyan, reset, strings.Join(parts, "  ·  "))
		}
	}

	if res.TLSEnum != nil {
		e := res.TLSEnum
		fmt.Printf("  %stls versions%s  %s\n", cyan, reset, strings.Join(e.SupportedVersions, ", "))
		if len(e.WeakVersions) > 0 {
			fmt.Printf("  %s✗  deprecated: %s%s\n", yellow, strings.Join(e.WeakVersions, ", "), reset)
		} else {
			fmt.Printf("  %s✓  no deprecated versions%s\n", green, reset)
		}
		if len(e.WeakCiphers) > 0 {
			fmt.Printf("  %s✗  weak ciphers: %s%s\n", yellow, strings.Join(e.WeakCiphers, ", "), reset)
		} else {
			fmt.Printf("  %s✓  no weak ciphers%s\n", green, reset)
		}
	}

	if scanner.IsHTTPService(res.Service, res.Port, res.TLS != nil) {
		if len(res.SecurityHeaders) == 0 {
			fmt.Printf("  %s✓  security headers OK%s\n", green, reset)
		} else {
			for _, f := range res.SecurityHeaders {
				color := yellow
				if f.Severity == "HIGH" {
					color = red
				}
				fmt.Printf("  %s✗  %s%s  %s\n", color, f.Header, reset, f.Detail)
			}
		}
	}

	if len(res.Vulnerabilities) > 0 {
		for _, cve := range res.Vulnerabilities {
			fmt.Printf("  %s✗  %s%s\n", red, cve, reset)
		}
	} else if len(res.Metadata) > 0 {
		fmt.Printf("  %s✓  no known CVEs%s\n", green, reset)
	}

	for _, ep := range res.Endpoints {
		if ep.StatusCode == 404 {
			continue
		}
		statusColor := green
		if ep.StatusCode >= 300 {
			statusColor = yellow
		}
		title := ""
		if ep.Title != "" {
			title = dim + "  \"" + ep.Title + "\"" + reset
		}
		fmt.Printf("  %s%d%s  %-32s%s\n", statusColor, ep.StatusCode, reset, ep.Path, title)
	}

	fmt.Println()
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
