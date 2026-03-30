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
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/config"
	"github.com/therandomsecurityguy/flan-go-scan/internal/dns"
	"github.com/therandomsecurityguy/flan-go-scan/internal/output"
	awsprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/aws"
	cfprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/cloudflare"
	kubeprovider "github.com/therandomsecurityguy/flan-go-scan/internal/providers/kubernetes"
	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
	"golang.org/x/sync/singleflight"
)

var version = "dev"

func printBanner() {
	logo := []string{
		"███████╗██╗      █████╗ ███╗   ██╗",
		"██╔════╝██║     ██╔══██╗████╗  ██║",
		"█████╗  ██║     ███████║██╔██╗ ██║",
		"██╔══╝  ██║     ██╔══██║██║╚██╗██║",
		"██║     ███████╗██║  ██║██║ ╚████║",
		"╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝",
	}
	side := []string{
		"",
		"swiss army knife network scanner",
		fmt.Sprintf("powered by Together AI (%s)", scanner.TogetherModel),
		"",
		fmt.Sprintf("[%s]", version),
		"",
	}

	fmt.Fprintln(os.Stderr)
	for i := range logo {
		fmt.Fprintf(os.Stderr, "\033[1;35m%s\033[0m", logo[i])
		if side[i] != "" {
			fmt.Fprintf(os.Stderr, "  \033[1;96m%s\033[0m", side[i])
		}
		fmt.Fprintln(os.Stderr)
	}
	fmt.Fprintln(os.Stderr)
}

func usage() {
	fmt.Fprintln(os.Stderr, "Usage:")
	fmt.Fprintln(os.Stderr, "  flan [flags]")
	fmt.Fprintln(os.Stderr)

	printUsageSection("GENERAL", [][2]string{
		{"-h, --help", "show help"},
		{"-v, --version", "show version"},
	})
	printUsageSection("TARGET", [][2]string{
		{"-t, -target string", "target host/IP to scan"},
		{"-l, -list string", `file containing targets (default "ips.txt")`},
		{"-d, -domain string", "domain to enumerate via DNS"},
	})
	printUsageSection("PORTS", [][2]string{
		{"-p, -ports string", "ports to scan (from config if not set)"},
		{"--top-ports string", "use top port list: 100, 1000, 2000, or 5000"},
		{"--subdomain-ports string", "domain mode port profile: web, standard, or full (default: web)"},
	})
	printUsageSection("CONFIGURATION", [][2]string{
		{"-c, -config string", `path to config file (default "config/config.yaml")`},
		{"--workers int", "number of concurrent scan workers"},
		{"--rate-limit int", "global scan requests per second"},
		{"--max-host-conns int", "max concurrent scan connections per host IP (0 disables)"},
		{"--fingerprint-only", "treat manual input as host:port targets and skip discovery"},
		{"-w, -wordlist string", "custom DNS subdomain wordlist file"},
		{"-r, -resolver string", "custom DNS resolver (ip:port)"},
		{"--cloudflare", "discover scan targets from Cloudflare zones"},
		{"--cloudflare-zones string", "comma-separated Cloudflare zone filter"},
		{"--cloudflare-include string", "comma-separated hostname include filters"},
		{"--cloudflare-exclude string", "comma-separated hostname exclude filters"},
		{"--cloudflare-inventory-out string", "write normalized Cloudflare inventory snapshot to this path"},
		{"--cloudflare-diff-against string", "compare the current Cloudflare inventory against a previous snapshot (defaults to --cloudflare-inventory-out when omitted)"},
		{"--cloudflare-delta-only", "scan only added/changed Cloudflare hosts when a previous snapshot is available"},
		{"--aws", "discover scan targets from AWS assets"},
		{"--aws-profile string", "AWS shared config profile to use"},
		{"--aws-regions string", "comma-separated AWS region filter"},
		{"--aws-include string", "comma-separated AWS target include filters"},
		{"--aws-exclude string", "comma-separated AWS target exclude filters"},
		{"--aws-inventory-out string", "write normalized AWS inventory snapshot to this path"},
		{"--aws-diff-against string", "compare the current AWS inventory against a previous snapshot (defaults to --aws-inventory-out when omitted)"},
		{"--aws-delta-only", "scan only added/changed AWS targets when a previous snapshot is available"},
		{"--kubeconfig string", "path to kubeconfig for Kubernetes validation"},
		{"--kube-context string", "optional kubeconfig context to use"},
		{"--kube-inventory", "enumerate externally reachable Kubernetes resources from the selected cluster"},
		{"--kube-inventory-out string", "write normalized Kubernetes inventory snapshot to this path"},
		{"--kube-diff-against string", "compare the current Kubernetes inventory against a previous snapshot (defaults to --kube-inventory-out when omitted)"},
		{"--kube-delta-only", "scan only added/changed Kubernetes resources when a previous snapshot is available"},
		{"--passive-only", "skip brute-force, use passive sources only"},
		{"--subdomains-only", "print discovered subdomains and exit (subfinder-style)"},
		{"--subfinder-sources string", "comma-separated passive sources override"},
		{"--subfinder-exclude-sources string", "comma-separated passive sources to exclude"},
		{"--subfinder-all", "use all subfinder sources (can be slower)"},
		{"--subfinder-recursive", "use only recursive-capable passive sources"},
		{"--subfinder-max-time int", "max passive enumeration time in minutes"},
		{"--subfinder-rate-limit int", "passive enumeration HTTP requests/second"},
		{"--subfinder-threads int", "passive enumeration threads"},
		{"--subfinder-provider-config string", "path to subfinder provider config"},
		{"--scan-cdn", "scan all ports on CDN hosts (default: 80,443 only)"},
		{"--udp", "enable UDP scanning (ports 53,123,161,500 by default)"},
		{"--crawl", "crawl HTTP/HTTPS services for endpoints and sensitive paths"},
		{"--crawl-depth int", "max crawl depth (default: 2)"},
		{"--tls-enum", "enumerate supported TLS versions and cipher suites (~60 connections per TLS port)"},
		{"--tls-verify", "verify TLS certificates (default: skip verification)"},
		{"--asn", "look up ASN and organization for each host via Cymru DNS"},
		{"--context string", "YAML file with asset context and policies for AI analysis"},
		{"--analyze", "AI-powered analysis via Together API (requires TOGETHER_API_KEY)"},
	})
	printUsageSection("OUTPUT", [][2]string{
		{"--json", "output in JSON format"},
		{"--jsonl", "output in JSONL format (streaming)"},
		{"--csv", "output in CSV format"},
	})

	fmt.Fprintln(os.Stderr, "EXAMPLES:")
	examples := []string{
		"flan -t scanme.nmap.org",
		"flan -l targets.txt --top-ports 1000",
		"flan -d example.net",
		"flan --cloudflare --cloudflare-zones example.net --cloudflare-include api.example.net",
		"AWS_PROFILE=<profile> flan --aws --aws-regions us-west-2",
		"flan --kubeconfig ~/.kube/config --kube-context prod-cluster",
		"flan --kubeconfig ~/.kube/config --kube-context prod-cluster --kube-inventory",
		"flan -d example.net --subdomains-only",
		`echo "10.0.0.0/24" | flan -l -`,
	}
	for _, ex := range examples {
		fmt.Fprintf(os.Stderr, "  %s\n", ex)
	}
	fmt.Fprintln(os.Stderr)
}

func printUsageSection(title string, rows [][2]string) {
	fmt.Fprintf(os.Stderr, "%s:\n", title)
	w := tabwriter.NewWriter(os.Stderr, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(w, "  %s\t%s\n", row[0], row[1])
	}
	_ = w.Flush()
	fmt.Fprintln(os.Stderr)
}

const (
	maxPorts     = 10000
	maxPortRange = 1000
)

func parsePorts(portStr string) ([]int, error) {
	if portStr == "" {
		return nil, nil
	}

	portStr = strings.TrimSpace(portStr)
	if portStr == "" {
		return nil, nil
	}

	var ports []int
	seen := make(map[int]bool)

	for _, part := range strings.Split(portStr, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		if strings.Contains(part, "-") {
			if strings.Count(part, "-") != 1 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range format: %s", part)
			}
			if !isNumericPortToken(bounds[0]) || !isNumericPortToken(bounds[1]) {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
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
			rangeSize := end - start + 1
			if rangeSize > maxPortRange {
				return nil, fmt.Errorf("port range too large: %d ports (max %d)", rangeSize, maxPortRange)
			}
			for p := start; p <= end; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
		} else {
			if !isNumericPortToken(part) {
				return nil, fmt.Errorf("invalid port %q", part)
			}
			p, err := strconv.Atoi(part)
			if err != nil {
				return nil, fmt.Errorf("invalid port %q: %w", part, err)
			}
			if p < 1 || p > 65535 {
				return nil, fmt.Errorf("port out of range: %d", p)
			}
			if !seen[p] {
				seen[p] = true
				ports = append(ports, p)
			}
		}

		if len(ports) > maxPorts {
			return nil, fmt.Errorf("too many ports: %d (max %d)", len(ports), maxPorts)
		}
	}
	return ports, nil
}

func isNumericPortToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
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
	subdomainPorts := flag.String("subdomain-ports", "", "")
	workersFlag := flag.Int("workers", 0, "")
	rateLimitFlag := flag.Int("rate-limit", 0, "")
	maxHostConnsFlag := flag.Int("max-host-conns", 0, "")
	fingerprintOnly := flag.Bool("fingerprint-only", false, "")
	wordlist := flag.String("wordlist", "", "")
	wordlistShort := flag.String("w", "", "")
	resolver := flag.String("resolver", "", "")
	resolverShort := flag.String("r", "", "")
	cloudflareFlag := flag.Bool("cloudflare", false, "")
	cloudflareZones := flag.String("cloudflare-zones", "", "")
	cloudflareInclude := flag.String("cloudflare-include", "", "")
	cloudflareExclude := flag.String("cloudflare-exclude", "", "")
	cloudflareInventoryOut := flag.String("cloudflare-inventory-out", "", "")
	cloudflareDiffAgainst := flag.String("cloudflare-diff-against", "", "")
	cloudflareDeltaOnly := flag.Bool("cloudflare-delta-only", false, "")
	awsFlag := flag.Bool("aws", false, "")
	awsProfile := flag.String("aws-profile", "", "")
	awsRegions := flag.String("aws-regions", "", "")
	awsInclude := flag.String("aws-include", "", "")
	awsExclude := flag.String("aws-exclude", "", "")
	awsInventoryOut := flag.String("aws-inventory-out", "", "")
	awsDiffAgainst := flag.String("aws-diff-against", "", "")
	awsDeltaOnly := flag.Bool("aws-delta-only", false, "")
	kubeconfigFlag := flag.String("kubeconfig", "", "")
	kubeContextFlag := flag.String("kube-context", "", "")
	kubeInventoryFlag := flag.Bool("kube-inventory", false, "")
	kubeInventoryOut := flag.String("kube-inventory-out", "", "")
	kubeDiffAgainst := flag.String("kube-diff-against", "", "")
	kubeDeltaOnly := flag.Bool("kube-delta-only", false, "")
	passiveOnly := flag.Bool("passive-only", false, "")
	subdomainsOnly := flag.Bool("subdomains-only", false, "")
	subfinderSources := flag.String("subfinder-sources", "", "")
	subfinderExcludeSources := flag.String("subfinder-exclude-sources", "", "")
	subfinderAll := flag.Bool("subfinder-all", false, "")
	subfinderRecursive := flag.Bool("subfinder-recursive", false, "")
	subfinderMaxTime := flag.Int("subfinder-max-time", 0, "")
	subfinderRateLimit := flag.Int("subfinder-rate-limit", 0, "")
	subfinderThreads := flag.Int("subfinder-threads", 0, "")
	subfinderProviderConfig := flag.String("subfinder-provider-config", "", "")
	scanCDN := flag.Bool("scan-cdn", false, "")
	udpFlag := flag.Bool("udp", false, "")
	crawlFlag := flag.Bool("crawl", false, "")
	crawlDepth := flag.Int("crawl-depth", 0, "")
	tlsEnumFlag := flag.Bool("tls-enum", false, "")
	tlsVerifyFlag := flag.Bool("tls-verify", false, "")
	asnFlag := flag.Bool("asn", false, "")
	contextFile := flag.String("context", "", "")
	analyze := flag.Bool("analyze", false, "")
	jsonFlag := flag.Bool("json", false, "")
	jsonlFlag := flag.Bool("jsonl", false, "")
	csvFlag := flag.Bool("csv", false, "")
	helpFlag := flag.Bool("help", false, "")
	helpShort := flag.Bool("h", false, "")
	versionFlag := flag.Bool("version", false, "")
	versionShort := flag.Bool("v", false, "")
	flag.Parse()

	if *helpFlag || *helpShort {
		usage()
		return
	}
	if *versionFlag || *versionShort {
		fmt.Println(version)
		return
	}

	printBanner()

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
	togetherAPIKey := strings.TrimSpace(os.Getenv("TOGETHER_API_KEY"))
	scanStarted := time.Now()
	if res == "" {
		res = strings.TrimSpace(cfg.DNS.Resolver)
	}

	if set["crawl-depth"] && *crawlDepth > 0 {
		cfg.Scan.CrawlDepth = *crawlDepth
	}
	if set["workers"] && *workersFlag > 0 {
		cfg.Scan.Workers = *workersFlag
	}
	if set["rate-limit"] && *rateLimitFlag >= 0 {
		cfg.Scan.RateLimit = *rateLimitFlag
	}
	if set["max-host-conns"] && *maxHostConnsFlag >= 0 {
		cfg.Scan.MaxHostConns = *maxHostConnsFlag
	}

	if set["subdomain-ports"] {
		cfg.Subdomain.PortProfile = *subdomainPorts
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
	cloudflareEnabled := *cloudflareFlag || cfg.Cloudflare.Enabled
	awsEnabled := *awsFlag || cfg.AWS.Enabled
	kubeOpts, kubeEnabled := selectKubernetesOptions(set, cfg, *kubeconfigFlag, *kubeContextFlag, *kubeInventoryFlag, *kubeInventoryOut, *kubeDiffAgainst, *kubeDeltaOnly)
	if *fingerprintOnly && (dom != "" || cloudflareEnabled || awsEnabled || *subdomainsOnly) {
		slog.Error("--fingerprint-only only supports manual -t/-l host:port inputs")
		os.Exit(1)
	}
	if kubeOpts.inventory && *fingerprintOnly {
		slog.Error("--kube-inventory cannot be combined with --fingerprint-only")
		os.Exit(1)
	}
	if *subdomainsOnly && dom == "" && !cloudflareEnabled && !awsEnabled {
		slog.Error("--subdomains-only requires -d/--domain, --cloudflare, or --aws")
		os.Exit(1)
	}
	if *subdomainsOnly {
		*passiveOnly = true
		slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn})))
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
	if togetherAPIKey != "" && (*analyze || prettyMode) {
		if err := scanner.ValidateAPIKey(); err != nil {
			if isTransientAPIValidationError(err) {
				slog.Debug("Together API key validation skipped due transient error", "err", err)
			} else {
				slog.Warn("Together API key validation failed", "err", err)
			}
		}
	}

	baseCtx, stop := context.WithCancel(context.Background())
	defer stop()
	ctx := baseCtx
	if cfg.Scan.MaxDuration > 0 {
		timeoutCtx, cancelTimeout := context.WithTimeout(baseCtx, cfg.Scan.MaxDuration)
		defer cancelTimeout()
		ctx = timeoutCtx
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		slog.Warn("received signal, shutting down", "signal", sig)
		stop()
	}()

	var hosts []string
	var endpointTargets []scanner.EndpointTarget
	noTargetsFromDelta := false

	if kubeEnabled {
		kubeClient := kubeprovider.NewClient(cfg.Kubernetes.Timeout)
		if kubeOpts.inventory {
			target, items, err := kubeClient.Inventory(ctx, kubeprovider.ValidateOptions{
				Kubeconfig: kubeOpts.kubeconfig,
				Context:    kubeOpts.context,
			})
			if err != nil {
				slog.Error("kubernetes inventory failed", "err", err)
				os.Exit(1)
			}
			slog.Info("kubernetes cluster validated", "context", target.Context, "cluster", target.Cluster, "server", target.Server)
			selectedItems := items
			snapshot := kubeprovider.BuildInventorySnapshot(scanStarted, target, items)
			diffAgainst := kubeOpts.diffAgainst
			if diffAgainst == "" && kubeOpts.inventoryOut != "" {
				diffAgainst = kubeOpts.inventoryOut
				slog.Info("kubernetes inventory diff base defaults to inventory output", "path", diffAgainst)
			}
			if diffAgainst != "" {
				previous, err := output.ReadKubernetesInventory(diffAgainst)
				if err == nil {
					diff := kubeprovider.DiffInventory(scanStarted, previous, snapshot)
					slog.Info("kubernetes inventory diff", "added", diff.AddedCount, "removed", diff.RemovedCount, "changed", diff.ChangedCount)
					if kubeOpts.deltaOnly {
						selectedItems = kubeprovider.ItemsFromDiff(diff)
						noTargetsFromDelta = len(selectedItems) == 0
						slog.Info("kubernetes delta scan selection", "resources", len(selectedItems))
					}
					if path, err := output.WriteKubernetesInventoryDiff(cfg.Output.Directory, kubeOpts.inventoryOut, diff); err != nil {
						slog.Warn("failed to write kubernetes inventory diff", "err", err)
					} else if path != "" {
						slog.Info("kubernetes inventory diff written", "path", path)
					}
				} else if !os.IsNotExist(err) {
					slog.Warn("failed to read previous kubernetes inventory", "path", diffAgainst, "err", err)
				} else if kubeOpts.deltaOnly {
					slog.Info("kubernetes delta scan fallback to full inventory; previous snapshot not found", "path", diffAgainst)
				}
			} else if kubeOpts.deltaOnly {
				slog.Info("kubernetes delta scan fallback to full inventory; no previous snapshot configured")
			}
			if path, err := output.WriteKubernetesInventory(cfg.Output.Directory, kubeOpts.inventoryOut, snapshot); err != nil {
				slog.Warn("failed to write kubernetes inventory", "err", err)
			} else if path != "" {
				slog.Info("kubernetes inventory written", "path", path)
			}
			for _, item := range selectedItems {
				endpointTargets = append(endpointTargets, scanner.EndpointTarget{
					Host: item.Host,
					Port: item.Port,
					Kubernetes: []scanner.KubernetesOrigin{{
						Cluster:   item.Cluster,
						Context:   item.Context,
						Namespace: item.Namespace,
						Kind:      item.Kind,
						Name:      item.Name,
						Exposure:  item.Exposure,
					}},
				})
			}
			slog.Info("kubernetes inventory complete", "resources", len(items), "scan_targets", len(endpointTargets))
			if len(selectedItems) == 0 && tgt == "" && dom == "" && !cloudflareEnabled && !awsEnabled && !set["list"] && !set["l"] {
				if kubeOpts.deltaOnly {
					slog.Info("no delta targets to scan")
				} else {
					slog.Info("no externally reachable kubernetes resources found")
				}
				return
			}
		} else {
			target, err := kubeClient.Validate(ctx, kubeprovider.ValidateOptions{
				Kubeconfig: kubeOpts.kubeconfig,
				Context:    kubeOpts.context,
			})
			if err != nil {
				slog.Error("kubernetes validation failed", "err", err)
				os.Exit(1)
			}
			slog.Info("kubernetes cluster validated", "context", target.Context, "cluster", target.Cluster, "server", target.Server)
			if validationOnlyKubernetesMode(set, dom, cloudflareEnabled, awsEnabled, kubeOpts.inventory, *fingerprintOnly) {
				slog.Info("no scan targets requested; kubeconfig validation complete")
				return
			}
		}
	}

	if tgt != "" && !*fingerprintOnly {
		hosts = append(hosts, tgt)
	}
	if cloudflareEnabled {
		tokenEnv := strings.TrimSpace(cfg.Cloudflare.TokenEnv)
		if tokenEnv == "" {
			tokenEnv = "CLOUDFLARE_API_TOKEN"
		}
		token := strings.TrimSpace(os.Getenv(tokenEnv))
		if token == "" {
			slog.Error("cloudflare token env var is not set", "env", tokenEnv)
			os.Exit(1)
		}

		client, err := cfprovider.NewClient(token, cfg.Cloudflare.Timeout)
		if err != nil {
			slog.Error("failed to initialize cloudflare client", "err", err)
			os.Exit(1)
		}

		discoverOpts := cfprovider.DiscoverOptions{
			Zones:   cfg.Cloudflare.Zones,
			Include: cfg.Cloudflare.Include,
			Exclude: cfg.Cloudflare.Exclude,
		}
		if set["cloudflare-zones"] {
			discoverOpts.Zones = splitCSV(*cloudflareZones)
		}
		if set["cloudflare-include"] {
			discoverOpts.Include = splitCSV(*cloudflareInclude)
		}
		if set["cloudflare-exclude"] {
			discoverOpts.Exclude = splitCSV(*cloudflareExclude)
		}

		slog.Info("discovering targets from Cloudflare", "zones", len(discoverOpts.Zones))
		assets, err := client.Discover(ctx, discoverOpts)
		if err != nil {
			slog.Error("cloudflare discovery failed", "err", err)
			os.Exit(1)
		}
		cfHosts := cfprovider.Hostnames(assets)
		selectedCFHosts := cfHosts
		inventoryOut := strings.TrimSpace(cfg.Cloudflare.InventoryOut)
		if set["cloudflare-inventory-out"] {
			inventoryOut = strings.TrimSpace(*cloudflareInventoryOut)
		}
		snapshot := cfprovider.BuildInventorySnapshot(scanStarted, assets, discoverOpts)
		diffAgainst := strings.TrimSpace(cfg.Cloudflare.DiffAgainst)
		if set["cloudflare-diff-against"] {
			diffAgainst = strings.TrimSpace(*cloudflareDiffAgainst)
		}
		deltaOnly := cfg.Cloudflare.DeltaOnly || *cloudflareDeltaOnly
		if diffAgainst == "" && inventoryOut != "" {
			diffAgainst = inventoryOut
			slog.Info("cloudflare inventory diff base defaults to inventory output", "path", diffAgainst)
		}
		if diffAgainst != "" {
			previous, err := output.ReadCloudflareInventory(diffAgainst)
			if err == nil {
				diff := cfprovider.DiffInventory(scanStarted, previous, snapshot)
				slog.Info("cloudflare inventory diff", "added", diff.AddedCount, "removed", diff.RemovedCount, "changed", diff.ChangedCount)
				if deltaOnly {
					selectedCFHosts = cfprovider.HostnamesFromDiff(diff)
					noTargetsFromDelta = len(selectedCFHosts) == 0
					slog.Info("cloudflare delta scan selection", "hosts", len(selectedCFHosts))
				}
				if path, err := output.WriteCloudflareInventoryDiff(cfg.Output.Directory, inventoryOut, diff); err != nil {
					slog.Warn("failed to write cloudflare inventory diff", "err", err)
				} else if path != "" {
					slog.Info("cloudflare inventory diff written", "path", path)
				}
			} else if !os.IsNotExist(err) {
				slog.Warn("failed to read previous cloudflare inventory", "path", diffAgainst, "err", err)
			} else if deltaOnly {
				slog.Info("cloudflare delta scan fallback to full inventory; previous snapshot not found", "path", diffAgainst)
			}
		} else if deltaOnly {
			slog.Info("cloudflare delta scan fallback to full inventory; no previous snapshot configured")
		}
		if path, err := output.WriteCloudflareInventory(cfg.Output.Directory, inventoryOut, snapshot); err != nil {
			slog.Warn("failed to write cloudflare inventory", "err", err)
		} else if path != "" {
			slog.Info("cloudflare inventory written", "path", path)
		}
		hosts = append(hosts, selectedCFHosts...)
		slog.Info("cloudflare discovery complete", "assets", len(assets), "hosts", len(cfHosts), "scan_hosts", len(selectedCFHosts))
		if *subdomainsOnly && dom == "" && !awsEnabled {
			for _, host := range discoveryOutputTargets(cfHosts, selectedCFHosts, deltaOnly) {
				fmt.Println(host)
			}
			return
		}
	}
	if awsEnabled {
		profile := strings.TrimSpace(cfg.AWS.Profile)
		if set["aws-profile"] {
			profile = strings.TrimSpace(*awsProfile)
		}

		client := awsprovider.NewClient(profile, cfg.AWS.Timeout)
		discoverOpts := awsprovider.DiscoverOptions{
			Regions: cfg.AWS.Regions,
			Include: cfg.AWS.Include,
			Exclude: cfg.AWS.Exclude,
		}
		if set["aws-regions"] {
			discoverOpts.Regions = splitCSV(*awsRegions)
		}
		if set["aws-include"] {
			discoverOpts.Include = splitCSV(*awsInclude)
		}
		if set["aws-exclude"] {
			discoverOpts.Exclude = splitCSV(*awsExclude)
		}

		slog.Info("discovering targets from AWS", "regions", len(discoverOpts.Regions), "profile", profileOrDefault(profile))
		assets, err := client.Discover(ctx, discoverOpts)
		if err != nil {
			slog.Error("aws discovery failed", "err", err)
			os.Exit(1)
		}
		awsTargets := awsprovider.Targets(assets)
		selectedAWSTargets := awsTargets

		inventoryOut := strings.TrimSpace(cfg.AWS.InventoryOut)
		if set["aws-inventory-out"] {
			inventoryOut = strings.TrimSpace(*awsInventoryOut)
		}
		snapshot := awsprovider.BuildInventorySnapshot(scanStarted, assets, discoverOpts)
		diffAgainst := strings.TrimSpace(cfg.AWS.DiffAgainst)
		if set["aws-diff-against"] {
			diffAgainst = strings.TrimSpace(*awsDiffAgainst)
		}
		deltaOnly := cfg.AWS.DeltaOnly || *awsDeltaOnly
		if diffAgainst == "" && inventoryOut != "" {
			diffAgainst = inventoryOut
			slog.Info("aws inventory diff base defaults to inventory output", "path", diffAgainst)
		}
		if diffAgainst != "" {
			previous, err := output.ReadAWSInventory(diffAgainst)
			if err == nil {
				diff := awsprovider.DiffInventory(scanStarted, previous, snapshot)
				slog.Info("aws inventory diff", "added", diff.AddedCount, "removed", diff.RemovedCount, "changed", diff.ChangedCount)
				if deltaOnly {
					selectedAWSTargets = awsprovider.TargetsFromDiff(diff)
					noTargetsFromDelta = len(selectedAWSTargets) == 0
					slog.Info("aws delta scan selection", "targets", len(selectedAWSTargets))
				}
				if path, err := output.WriteAWSInventoryDiff(cfg.Output.Directory, inventoryOut, diff); err != nil {
					slog.Warn("failed to write aws inventory diff", "err", err)
				} else if path != "" {
					slog.Info("aws inventory diff written", "path", path)
				}
			} else if !os.IsNotExist(err) {
				slog.Warn("failed to read previous aws inventory", "path", diffAgainst, "err", err)
			} else if deltaOnly {
				slog.Info("aws delta scan fallback to full inventory; previous snapshot not found", "path", diffAgainst)
			}
		} else if deltaOnly {
			slog.Info("aws delta scan fallback to full inventory; no previous snapshot configured")
		}
		if path, err := output.WriteAWSInventory(cfg.Output.Directory, inventoryOut, snapshot); err != nil {
			slog.Warn("failed to write aws inventory", "err", err)
		} else if path != "" {
			slog.Info("aws inventory written", "path", path)
		}
		hosts = append(hosts, selectedAWSTargets...)
		slog.Info("aws discovery complete", "assets", len(assets), "targets", len(awsTargets), "scan_targets", len(selectedAWSTargets))
		if *subdomainsOnly && dom == "" && !cloudflareEnabled {
			for _, target := range discoveryOutputTargets(awsTargets, selectedAWSTargets, deltaOnly) {
				fmt.Println(target)
			}
			return
		}
	}
	if *subdomainsOnly && dom == "" && len(hosts) > 0 {
		for _, host := range normalizeDiscoveredHosts(hosts) {
			fmt.Println(host)
		}
		return
	}
	if dom != "" {
		slog.Info("enumerating subdomains", "domain", dom)

		slog.Info("running passive enumeration")
		passiveOpts := dns.DefaultPassiveOptions(cfg.Scan.Timeout)
		passiveOpts.Sources = splitCSV(cfg.Subdomain.Sources)
		passiveOpts.ExcludeSources = splitCSV(cfg.Subdomain.ExcludeSources)
		passiveOpts.AllSources = cfg.Subdomain.AllSources
		passiveOpts.RecursiveOnly = cfg.Subdomain.RecursiveOnly
		passiveOpts.MaxTimeMinutes = cfg.Subdomain.MaxTime
		passiveOpts.RateLimit = cfg.Subdomain.RateLimit
		passiveOpts.Threads = cfg.Subdomain.Threads
		passiveOpts.ProviderConfig = cfg.Subdomain.ProviderConfig
		if set["subfinder-sources"] {
			passiveOpts.Sources = splitCSV(*subfinderSources)
		}
		if set["subfinder-exclude-sources"] {
			passiveOpts.ExcludeSources = splitCSV(*subfinderExcludeSources)
		}
		if set["subfinder-all"] {
			passiveOpts.AllSources = *subfinderAll
		}
		if set["subfinder-recursive"] {
			passiveOpts.RecursiveOnly = *subfinderRecursive
		}
		if set["subfinder-max-time"] && *subfinderMaxTime > 0 {
			passiveOpts.MaxTimeMinutes = *subfinderMaxTime
		}
		if set["subfinder-rate-limit"] && *subfinderRateLimit >= 0 {
			passiveOpts.RateLimit = *subfinderRateLimit
		}
		if set["subfinder-threads"] && *subfinderThreads > 0 {
			passiveOpts.Threads = *subfinderThreads
		}
		if set["subfinder-provider-config"] {
			passiveOpts.ProviderConfig = strings.TrimSpace(*subfinderProviderConfig)
		}
		passiveHosts, err := dns.PassiveEnumerate(ctx, dom, passiveOpts)
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
				if result.Hostname != "" {
					hosts = append(hosts, result.Hostname)
					continue
				}
				if result.IP != nil {
					hosts = append(hosts, result.IP.String())
				}
			}
			slog.Info("brute-force enumeration complete", "hosts", len(enumResults))
		}

		hosts = normalizeDiscoveredHosts(hosts)
		slog.Info("subdomain enumeration complete", "unique_hosts", len(hosts))
		if *subdomainsOnly {
			for _, host := range hosts {
				fmt.Println(host)
			}
			return
		}

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
	}
	if tgt == "" && dom == "" && !cloudflareEnabled && !awsEnabled && len(endpointTargets) == 0 {
		if *fingerprintOnly {
			var r *os.File
			if ipsFile == "-" {
				r = os.Stdin
			} else {
				r, err = os.Open(ipsFile)
				if err != nil {
					slog.Error("failed to read endpoint targets", "err", err)
					os.Exit(1)
				}
				defer r.Close()
			}
			endpointTargets, err = scanner.ParseEndpointTargets(r)
			if err != nil {
				slog.Error("failed to read endpoint targets", "err", err)
				os.Exit(1)
			}
		} else {
			hosts, err = readHosts(ipsFile)
			if err != nil {
				slog.Error("failed to read hosts", "err", err)
				os.Exit(1)
			}
		}
	}

	if *fingerprintOnly && tgt != "" {
		endpointTargets, err = scanner.ParseEndpointTargets(strings.NewReader(tgt))
		if err != nil {
			slog.Error("invalid fingerprint-only target", "err", err)
			os.Exit(1)
		}
	}

	if len(hosts) == 0 && len(endpointTargets) == 0 {
		if noTargetsFromDelta {
			slog.Info("no delta targets to scan")
			return
		}
		slog.Error("no hosts to scan, provide -t, -d, -l, --cloudflare, --aws, or --kube-inventory")
		os.Exit(1)
	}
	inputTargets := len(hosts) + len(endpointTargets)

	var ports []int
	if !*fingerprintOnly {
		ports, err = selectScanPorts(dom != "", set, *topPorts, portStr, cfg)
		if err != nil {
			slog.Error("invalid port configuration", "err", err)
			os.Exit(1)
		}
		inputCount := len(hosts) + len(endpointTargets)
		if inputCount == 0 {
			inputCount = len(hosts)
		}
		guardPortCount := len(ports)
		if guardPortCount == 0 && len(endpointTargets) > 0 {
			guardPortCount = 1
		}
		if err := enforceScanGuardrails(inputCount, guardPortCount, cfg); err != nil {
			slog.Error("scan blocked by guardrails", "err", err)
			os.Exit(1)
		}
	} else if err := enforceScanGuardrails(len(endpointTargets), 1, cfg); err != nil {
		slog.Error("scan blocked by guardrails", "err", err)
		os.Exit(1)
	}

	dnsCache := dns.NewDNSCache(cfg.DNS.TTL, cfg.DNS.LookupTimeout, res, cfg.DNS.FallbackResolvers)
	if cfg.Scan.RateLimit <= 0 {
		slog.Warn("invalid scan.rate_limit; clamping to 1 request/sec", "rate_limit", cfg.Scan.RateLimit)
	}
	limiter := scanner.NewRateLimiter(cfg.Scan.RateLimit)
	checkpoint, err := scanner.NewCheckpoint(cfg.Checkpoint.File)
	if err != nil {
		slog.Error("invalid checkpoint path", "err", err)
		os.Exit(1)
	}
	cveLookup := scanner.NewCVELookup()
	udpEnabled := *udpFlag || cfg.Scan.UDP

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

	resolveInputs := make([]resolveInput, 0, len(hosts)+len(endpointTargets))
	for _, host := range hosts {
		resolveInputs = append(resolveInputs, resolveInput{Host: host})
	}
	for _, endpoint := range endpointTargets {
		resolveInputs = append(resolveInputs, resolveInput{
			Host:       endpoint.Host,
			Port:       endpoint.Port,
			ExactPort:  true,
			Kubernetes: append([]scanner.KubernetesOrigin(nil), endpoint.Kubernetes...),
		})
	}
	targets := resolveTargets(ctx, resolveInputs, dnsCache, *asnFlag, cfg.Scan.Timeout, res, cfg.Scan.Workers)
	guardPorts := len(ports)
	if *fingerprintOnly || len(endpointTargets) > 0 {
		guardPorts = 1
	}
	if err := enforceScanGuardrails(len(targets), guardPorts, cfg); err != nil {
		slog.Error("scan blocked by guardrails after DNS resolution", "err", err)
		os.Exit(1)
	}
	resolvedTargets := len(targets)

	tlsVerify := *tlsVerifyFlag

	if cfg.Scan.Discovery && !udpEnabled && !*fingerprintOnly {
		targets = discoverAliveTargets(ctx, targets, ports, cfg.Scan.Workers, cfg.Scan.Timeout)
	} else if cfg.Scan.Discovery && udpEnabled && !*fingerprintOnly {
		slog.Info("skipping discovery filter for UDP mode to avoid dropping UDP-only hosts", "targets", len(targets))
	} else if *fingerprintOnly {
		slog.Info("skipping discovery filter for fingerprint-only mode", "targets", len(targets))
	}
	aliveTargets := len(targets)
	metaInput := scanMetadataInput{
		mode:            scanMode(dom != "", cloudflareEnabled, awsEnabled, kubeOpts.inventory),
		inputTargets:    inputTargets,
		resolvedTargets: resolvedTargets,
		aliveTargets:    aliveTargets,
		portsPerTarget:  guardPorts,
		rateLimit:       cfg.Scan.RateLimit,
		workers:         cfg.Scan.Workers,
		maxHostConns:    cfg.Scan.MaxHostConns,
		guardMaxTargets: cfg.Scan.MaxTargets,
		guardMaxPorts:   cfg.Scan.MaxPortsHost,
		guardMaxDur:     cfg.Scan.MaxDuration,
		dnsStats:        dnsCache.Stats(),
	}

	if len(targets) == 0 {
		slog.Info("no live hosts found")
		writeScanMetadata(cfg.Output.Directory, buildScanMetadata(scanStarted, time.Now(), ctx.Err(), metaInput))
		return
	}

	cdnDetector := scanner.NewCDNDetector()
	cdnHosts := make(map[string]string)
	for _, target := range targets {
		if cdn := cdnDetector.Detect(target.IP); cdn != "" {
			cdnHosts[target.IP] = cdn
		}
	}
	if len(cdnHosts) > 0 {
		slog.Info("CDN hosts detected", "count", len(cdnHosts))
	}

	cdnSkipPorts := map[int]bool{
		80:  true,
		443: true,
	}

	progress := scanner.NewProgress(len(targets))
	statsInterval := 5
	if cfg.Scan.StatsInterval > 0 {
		statsInterval = cfg.Scan.StatsInterval
	}
	progressCtx, stopProgress := context.WithCancel(ctx)
	if !prettyMode {
		go progress.Run(progressCtx, time.Duration(statsInterval)*time.Second)
	}

	checkpointCtx, stopCheckpoint := context.WithCancel(ctx)
	defer stopCheckpoint()
	var checkpointWg sync.WaitGroup
	checkpointWg.Add(1)
	go func() {
		defer checkpointWg.Done()
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-checkpointCtx.Done():
				return
			case <-ticker.C:
				if err := checkpoint.Flush(); err != nil {
					slog.Warn("periodic checkpoint flush failed", "err", err)
				}
			}
		}
	}()

	rawResultsCh := make(chan scanner.ScanResult, 100)
	resultsCh := make(chan scanner.ScanResult, 100)
	cveWorkers := 4
	if cfg.Scan.Workers > 0 && cfg.Scan.Workers < cveWorkers {
		cveWorkers = cfg.Scan.Workers
	}
	var cveWg sync.WaitGroup
	for i := 0; i < cveWorkers; i++ {
		cveWg.Add(1)
		go func() {
			defer cveWg.Done()
			for res := range rawResultsCh {
				enrichResultVulnerabilities(ctx, &res, cveLookup)
				resultsCh <- res
			}
		}()
	}
	go func() {
		cveWg.Wait()
		close(resultsCh)
	}()

	var collectWg sync.WaitGroup
	var results []scanner.ScanResult
	storeResults := shouldStoreResults(jsonlWriter, *analyze, prettyMode, scanCtx, togetherAPIKey)

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
			if storeResults {
				results = append(results, res)
			}
		}
	}()

	pool := scanner.NewWorkerPool(cfg.Scan.Workers)
	hostLimiter := scanner.NewHostLimiter(cfg.Scan.MaxHostConns)
	var wg sync.WaitGroup

	targetPorts := make(map[string][]int, len(targets))
	targetMeta := make(map[string]scanTarget, len(targets))
	remainingByTarget := make(map[string]*atomic.Int64, len(targets))
	targetOrder := make([]string, 0, len(targets))
	maxHostPorts := 0
	portsScheduled := 0

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}
		cdn := cdnHosts[target.IP]
		targetKey := target.CheckpointKey
		hostPorts := make([]int, 0, len(ports))
		if target.ExactPort {
			if target.Port > 0 && !checkpoint.ShouldSkip(targetKey, target.Port) {
				hostPorts = append(hostPorts, target.Port)
			}
		} else {
			for _, port := range ports {
				if ctx.Err() != nil {
					break
				}
				if cdn != "" && !*scanCDN && !cdnSkipPorts[port] {
					continue
				}
				if checkpoint.ShouldSkip(targetKey, port) {
					continue
				}
				hostPorts = append(hostPorts, port)
			}
		}
		if len(hostPorts) == 0 {
			progress.HostsDone.Add(1)
			continue
		}
		targetPorts[targetKey] = hostPorts
		targetMeta[targetKey] = target
		targetOrder = append(targetOrder, targetKey)
		portsScheduled += len(hostPorts)
		remaining := &atomic.Int64{}
		remaining.Store(int64(len(hostPorts)))
		remainingByTarget[targetKey] = remaining
		if len(hostPorts) > maxHostPorts {
			maxHostPorts = len(hostPorts)
		}
	}

	if storeResults {
		results = make([]scanner.ScanResult, 0, portsScheduled/3)
	}

	for idx := 0; idx < maxHostPorts; idx++ {
		for _, targetKey := range targetOrder {
			hostPorts, ok := targetPorts[targetKey]
			if !ok || idx >= len(hostPorts) {
				continue
			}
			remaining := remainingByTarget[targetKey]
			port := hostPorts[idx]
			if ctx.Err() != nil {
				if remaining.Add(-1) == 0 {
					progress.HostsDone.Add(1)
				}
				continue
			}

			target := targetMeta[targetKey]
			cdn := cdnHosts[target.IP]
			pool.Acquire()
			wg.Add(1)
			go func(target scanTarget, port int, remaining *atomic.Int64, cdn string) {
				defer wg.Done()
				defer pool.Release()
				defer func() {
					if remaining.Add(-1) == 0 {
						progress.HostsDone.Add(1)
					}
				}()
				if ctx.Err() != nil {
					return
				}
				releaseHost, err := hostLimiter.Acquire(ctx, target.IP)
				if err != nil {
					return
				}
				defer releaseHost()
				if err := limiter.Wait(ctx); err != nil {
					return
				}
				progress.PortsScanned.Add(1)
				res := scanTCPPort(
					ctx,
					target.IP,
					port,
					target.Hostname,
					cdn,
					cfg,
					tcpScanOptions{
						crawl:     *crawlFlag,
						tlsEnum:   *tlsEnumFlag,
						tlsVerify: tlsVerify,
					},
					target.ASN,
					target.Org,
					target.PTR,
					target.Kubernetes,
				)
				if res == nil {
					return
				}
				progress.ServicesFound.Add(1)
				rawResultsCh <- *res
				checkpoint.Save(target.CheckpointKey, port)
			}(target, port, remaining, cdn)
		}
	}
	wg.Wait()

	if udpEnabled {
		udpPortStr := cfg.Scan.UDPPorts
		udpPorts, err := parsePorts(udpPortStr)
		if err != nil {
			slog.Error("invalid UDP port configuration", "err", err)
			os.Exit(1)
		}
		var udpWg sync.WaitGroup
		seenUDPHosts := make(map[string]struct{})
		udpKubernetesByIP := make(map[string][]scanner.KubernetesOrigin)
		for _, target := range targets {
			udpKubernetesByIP[target.IP] = mergeKubernetesOrigins(udpKubernetesByIP[target.IP], target.Kubernetes)
		}
		for _, target := range targets {
			ip := target.IP
			if _, exists := seenUDPHosts[ip]; exists {
				continue
			}
			seenUDPHosts[ip] = struct{}{}
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
					releaseHost, err := hostLimiter.Acquire(ctx, ip)
					if err != nil {
						return
					}
					defer releaseHost()
					if err := limiter.Wait(ctx); err != nil {
						return
					}
					fp := scanner.FingerprintUDP(ip, port, cfg.Scan.Timeout)
					if fp == nil {
						return
					}
					progress.ServicesFound.Add(1)
					rawResultsCh <- scanner.ScanResult{
						Host:       ip,
						Port:       port,
						Protocol:   "udp",
						Service:    fp.Service,
						Version:    fp.Version,
						Metadata:   fp.Metadata,
						Kubernetes: append([]scanner.KubernetesOrigin(nil), udpKubernetesByIP[ip]...),
					}
				}(ip, port)
			}
		}
		udpWg.Wait()
	}

	close(rawResultsCh)
	collectWg.Wait()
	stopCheckpoint()
	checkpointWg.Wait()

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

	if prettyMode && !*analyze && togetherAPIKey != "" && len(results) > 0 {
		fmt.Print("\033[2m  Analyzing...\033[0m\r")
		brief, err := scanner.AnalyzeBrief(ctx, results, scanCtx)
		fmt.Print("                \r")
		if err == nil {
			fmt.Println()
			fmt.Printf("\033[2m  ──────────────\033[0m \033[1m\033[36mAI Analysis\033[0m \033[2m──────────────\033[0m\n\n")
			printAnalysis(brief)
			fmt.Printf("\033[2m  Powered by Together AI (%s)\033[0m\n", scanner.TogetherModel)
			fmt.Println()
		} else {
			fmt.Println()
			fmt.Printf("  \033[33m~\033[0m  AI summary skipped: %s\n\n", summarizeAnalysisError(err))
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
			fmt.Printf("\033[2m  Powered by Together AI (%s)\033[0m\n", scanner.TogetherModel)
			fmt.Println()
		}
	}

	metaInput.portsScheduled = portsScheduled
	metaInput.portsScanned = progress.PortsScanned.Load()
	metaInput.servicesFound = progress.ServicesFound.Load()
	metaInput.dnsStats = dnsCache.Stats()
	writeScanMetadata(cfg.Output.Directory, buildScanMetadata(scanStarted, time.Now(), ctx.Err(), metaInput))

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
			fmt.Printf("%s:%d [%s %s] TLS:%v %s\n", displayHost(res.Host, res.Hostname), res.Port, res.Service, res.Version, res.TLS != nil, res.Banner)
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
		bold+cyan, fmt.Sprintf("%s:%d", displayHost(res.Host, res.Hostname), res.Port), reset,
		cyan, res.Service, reset,
		version, tls,
	)

	if res.PTR != "" || res.ASN != "" {
		var meta []string
		if res.PTR != "" {
			meta = append(meta, "PTR "+res.PTR)
		}
		if res.ASN != "" {
			label := "AS" + res.ASN
			if res.Org != "" {
				label += " " + res.Org
			}
			meta = append(meta, label)
		}
		fmt.Printf("  %smeta%s  %s\n", cyan, reset, strings.Join(meta, "  ·  "))
	}

	if len(res.Kubernetes) > 0 {
		values := make([]string, 0, len(res.Kubernetes))
		for _, origin := range res.Kubernetes {
			values = append(values, formatKubernetesOrigin(origin))
		}
		fmt.Printf("  %skube%s  %s\n", cyan, reset, strings.Join(values, "  ·  "))
	}

	if len(res.Products) > 0 || res.App != nil {
		var parts []string
		for _, product := range res.Products {
			if product.Confidence != "" {
				parts = append(parts, product.Name+" ("+strings.ToLower(product.Confidence)+")")
			} else {
				parts = append(parts, product.Name)
			}
		}
		if res.App != nil {
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
		eligible, statusCode := headerInspectionEligible(res)
		displayFindings := displaySecurityHeaderFindings(res)
		if !eligible {
			fmt.Printf("  %s~  security headers skipped on HTTP status %d%s\n", dim, statusCode, reset)
		} else if len(displayFindings) == 0 {
			fmt.Printf("  %s✓  security headers OK%s\n", green, reset)
		} else {
			for _, f := range displayFindings {
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

func splitCSV(input string) []string {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	parts := strings.Split(input, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		value := strings.TrimSpace(part)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

type kubernetesOptions struct {
	kubeconfig   string
	context      string
	inventory    bool
	inventoryOut string
	diffAgainst  string
	deltaOnly    bool
}

func selectKubernetesOptions(set map[string]bool, cfg *config.Config, kubeconfigFlag string, kubeContextFlag string, kubeInventoryFlag bool, kubeInventoryOut string, kubeDiffAgainst string, kubeDeltaOnly bool) (kubernetesOptions, bool) {
	opts := kubernetesOptions{
		kubeconfig:   strings.TrimSpace(cfg.Kubernetes.Kubeconfig),
		context:      strings.TrimSpace(cfg.Kubernetes.Context),
		inventory:    cfg.Kubernetes.Inventory,
		inventoryOut: strings.TrimSpace(cfg.Kubernetes.InventoryOut),
		diffAgainst:  strings.TrimSpace(cfg.Kubernetes.DiffAgainst),
		deltaOnly:    cfg.Kubernetes.DeltaOnly,
	}
	if set["kubeconfig"] {
		opts.kubeconfig = strings.TrimSpace(kubeconfigFlag)
	}
	if set["kube-context"] {
		opts.context = strings.TrimSpace(kubeContextFlag)
	}
	if set["kube-inventory"] {
		opts.inventory = kubeInventoryFlag
	}
	if set["kube-inventory-out"] {
		opts.inventoryOut = strings.TrimSpace(kubeInventoryOut)
	}
	if set["kube-diff-against"] {
		opts.diffAgainst = strings.TrimSpace(kubeDiffAgainst)
	}
	if set["kube-delta-only"] {
		opts.deltaOnly = kubeDeltaOnly
	}
	if opts.inventoryOut != "" || opts.diffAgainst != "" || opts.deltaOnly {
		opts.inventory = true
	}
	enabled := cfg.Kubernetes.Enabled ||
		opts.inventory ||
		set["kubeconfig"] ||
		set["kube-context"] ||
		set["kube-inventory"] ||
		set["kube-inventory-out"] ||
		set["kube-diff-against"] ||
		set["kube-delta-only"] ||
		opts.kubeconfig != "" ||
		opts.context != "" ||
		opts.inventoryOut != "" ||
		opts.diffAgainst != "" ||
		opts.deltaOnly
	return opts, enabled
}

func validationOnlyKubernetesMode(set map[string]bool, domain string, cloudflareEnabled bool, awsEnabled bool, kubeInventory bool, fingerprintOnly bool) bool {
	return !set["target"] &&
		!set["t"] &&
		!set["list"] &&
		!set["l"] &&
		domain == "" &&
		!cloudflareEnabled &&
		!awsEnabled &&
		!kubeInventory &&
		!fingerprintOnly
}

func normalizeDiscoveredHosts(hosts []string) []string {
	seen := make(map[string]struct{}, len(hosts))
	out := make([]string, 0, len(hosts))
	for _, raw := range hosts {
		host := strings.TrimSpace(raw)
		if host == "" {
			continue
		}
		key := host
		if ip := net.ParseIP(host); ip != nil {
			key = ip.String()
			host = key
		} else {
			host = strings.TrimSuffix(strings.ToLower(host), ".")
			key = host
		}
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, host)
	}
	return out
}

func selectScanPorts(isDomainMode bool, set map[string]bool, topPortsValue, portStr string, cfg *config.Config) ([]int, error) {
	portsExplicit := set["ports"] || set["p"] || set["top-ports"]
	if isDomainMode && !portsExplicit {
		return portsForSubdomainProfile(cfg.Subdomain.PortProfile)
	}

	switch topPortsValue {
	case "100":
		return append([]int(nil), scanner.TopPorts100...), nil
	case "1000":
		return append([]int(nil), scanner.TopPorts1000...), nil
	case "2000":
		return append([]int(nil), scanner.TopPorts2000...), nil
	case "5000":
		return append([]int(nil), scanner.TopPorts5000...), nil
	case "":
		if portStr != "" {
			return parsePorts(portStr)
		}
		return parsePorts(cfg.Scan.Ports)
	default:
		return nil, fmt.Errorf("invalid --top-ports value %q, use 100, 1000, 2000, or 5000", topPortsValue)
	}
}

func portsForSubdomainProfile(profile string) ([]int, error) {
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "", "web":
		return append([]int(nil), scanner.SubdomainWebPorts...), nil
	case "standard":
		return append([]int(nil), scanner.TopPorts100...), nil
	case "full":
		return append([]int(nil), scanner.TopPorts1000...), nil
	default:
		return nil, fmt.Errorf("invalid subdomain port profile %q, use web, standard, or full", profile)
	}
}

type scanTarget struct {
	Hostname      string
	IP            string
	Port          int
	ExactPort     bool
	ASN           string
	Org           string
	PTR           string
	CheckpointKey string
	Kubernetes    []scanner.KubernetesOrigin
}

type resolveInput struct {
	Host       string
	Port       int
	ExactPort  bool
	Kubernetes []scanner.KubernetesOrigin
}

func resolveTargets(
	ctx context.Context,
	inputs []resolveInput,
	dnsCache *dns.DNSCache,
	asnEnabled bool,
	timeout time.Duration,
	resolver string,
	workers int,
) []scanTarget {
	if workers <= 0 {
		workers = 1
	}
	if workers > len(inputs) {
		workers = len(inputs)
	}
	if workers == 0 {
		return nil
	}

	type ipMetadata struct {
		asn string
		org string
		ptr string
	}

	var ipMetaCache sync.Map
	var ipMetaSF singleflight.Group
	getIPMetadata := func(ip string) ipMetadata {
		if cached, ok := ipMetaCache.Load(ip); ok {
			return cached.(ipMetadata)
		}
		value, _, _ := ipMetaSF.Do(ip, func() (interface{}, error) {
			if cached, ok := ipMetaCache.Load(ip); ok {
				return cached, nil
			}
			asn, org := scanner.LookupASN(ctx, ip, timeout, resolver)
			ptr := ""
			if ptrs := scanner.LookupPTR(ip); len(ptrs) > 0 {
				ptr = ptrs[0]
			}
			meta := ipMetadata{asn: asn, org: org, ptr: ptr}
			ipMetaCache.Store(ip, meta)
			return meta, nil
		})
		if value == nil {
			return ipMetadata{}
		}
		return value.(ipMetadata)
	}

	inputCh := make(chan resolveInput, workers)
	targetCh := make(chan scanTarget, workers*4)
	var workersWg sync.WaitGroup
	for i := 0; i < workers; i++ {
		workersWg.Add(1)
		go func() {
			defer workersWg.Done()
			for input := range inputCh {
				if ctx.Err() != nil {
					return
				}
				host := strings.TrimSpace(input.Host)
				if host == "" {
					continue
				}
				resolvedIPs, err := dnsCache.LookupContext(ctx, host)
				if err != nil {
					slog.Warn("DNS lookup failed", "host", host, "err", err)
					continue
				}

				hostname := ""
				if net.ParseIP(host) == nil {
					hostname = strings.TrimSuffix(strings.ToLower(host), ".")
				}

				for _, ip := range resolvedIPs {
					ipStr := ip.String()
					target := scanTarget{
						Hostname:      hostname,
						IP:            ipStr,
						Port:          input.Port,
						ExactPort:     input.ExactPort,
						CheckpointKey: targetCheckpointKey(hostname, ipStr),
						Kubernetes:    append([]scanner.KubernetesOrigin(nil), input.Kubernetes...),
					}
					if asnEnabled {
						meta := getIPMetadata(ipStr)
						target.ASN = meta.asn
						target.Org = meta.org
						target.PTR = meta.ptr
					}

					select {
					case <-ctx.Done():
						return
					case targetCh <- target:
					}
				}
			}
		}()
	}

sendLoop:
	for _, input := range inputs {
		select {
		case <-ctx.Done():
			break sendLoop
		case inputCh <- input:
		}
	}
	close(inputCh)
	go func() {
		workersWg.Wait()
		close(targetCh)
	}()

	indexByKey := make(map[string]int)
	targets := make([]scanTarget, 0, len(inputs))
	for target := range targetCh {
		key := target.CheckpointKey
		if target.ExactPort && target.Port > 0 {
			key = fmt.Sprintf("%s:%d", key, target.Port)
		}
		if idx, exists := indexByKey[key]; exists {
			targets[idx].Kubernetes = mergeKubernetesOrigins(targets[idx].Kubernetes, target.Kubernetes)
			continue
		}
		indexByKey[key] = len(targets)
		targets = append(targets, target)
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].CheckpointKey == targets[j].CheckpointKey {
			return targets[i].Port < targets[j].Port
		}
		return targets[i].CheckpointKey < targets[j].CheckpointKey
	})
	return targets
}

func targetCheckpointKey(hostname, ip string) string {
	if hostname == "" {
		return ip
	}
	return hostname + "|" + ip
}

func discoverAliveTargets(ctx context.Context, targets []scanTarget, ports []int, workers int, timeout time.Duration) []scanTarget {
	probesByIP := make(map[string]map[int]struct{}, len(targets))
	for _, target := range targets {
		portSet := probesByIP[target.IP]
		if portSet == nil {
			portSet = make(map[int]struct{}, len(ports)+1)
			probesByIP[target.IP] = portSet
		}
		if target.ExactPort && target.Port > 0 {
			portSet[target.Port] = struct{}{}
			continue
		}
		for _, port := range ports {
			portSet[port] = struct{}{}
		}
	}

	probes := make([]discoveryProbe, 0, len(probesByIP))
	for ip, portSet := range probesByIP {
		probePorts := make([]int, 0, len(portSet))
		for port := range portSet {
			probePorts = append(probePorts, port)
		}
		sort.Ints(probePorts)
		probes = append(probes, discoveryProbe{ip: ip, ports: probePorts})
	}

	aliveIPs := discoverAliveHosts(ctx, probes, workers, timeout)
	aliveSet := make(map[string]struct{}, len(aliveIPs))
	for _, ip := range aliveIPs {
		aliveSet[ip] = struct{}{}
	}

	filtered := make([]scanTarget, 0, len(targets))
	for _, target := range targets {
		if _, ok := aliveSet[target.IP]; ok {
			filtered = append(filtered, target)
		}
	}
	return filtered
}

type discoveryProbe struct {
	ip    string
	ports []int
}

func discoverAliveHosts(ctx context.Context, probes []discoveryProbe, workers int, timeout time.Duration) []string {
	slog.Info("running host discovery", "targets", len(probes))
	type aliveResult struct {
		ip    string
		alive bool
	}
	results := make(chan aliveResult, len(probes))
	discoveryPool := scanner.NewWorkerPool(workers)
	var discoveryWg sync.WaitGroup

	for _, probe := range probes {
		discoveryPool.Acquire()
		discoveryWg.Add(1)
		go func(probe discoveryProbe) {
			defer discoveryWg.Done()
			defer discoveryPool.Release()
			results <- aliveResult{ip: probe.ip, alive: scanner.IsHostAlive(ctx, probe.ip, probe.ports, timeout)}
		}(probe)
	}
	discoveryWg.Wait()
	close(results)

	var alive []string
	for r := range results {
		if r.alive {
			alive = append(alive, r.ip)
		}
	}
	slog.Info("host discovery complete", "alive", len(alive), "filtered", len(probes)-len(alive))
	return alive
}

func enrichResultVulnerabilities(ctx context.Context, res *scanner.ScanResult, cveLookup *scanner.CVELookup) {
	if res == nil || len(res.Metadata) == 0 {
		return
	}
	var meta struct {
		CPEs []string `json:"cpes"`
	}
	if err := json.Unmarshal(res.Metadata, &meta); err != nil || len(meta.CPEs) == 0 {
		return
	}

	const (
		maxCPELookups   = 2
		cveLookupWindow = 4 * time.Second
	)

	seenCPEs := make(map[string]struct{})
	seenCVEs := make(map[string]struct{})
	var vulns []string

	for _, cpe := range meta.CPEs {
		if cpe == "" {
			continue
		}
		if _, seen := seenCPEs[cpe]; seen {
			continue
		}
		if len(seenCPEs) >= maxCPELookups {
			break
		}
		seenCPEs[cpe] = struct{}{}

		lookupCtx, cancel := context.WithTimeout(ctx, cveLookupWindow)
		for _, cve := range cveLookup.Lookup(lookupCtx, cpe) {
			if _, seen := seenCVEs[cve.ID]; seen {
				continue
			}
			seenCVEs[cve.ID] = struct{}{}
			vulns = append(vulns, cve.ID)
		}
		cancel()
	}
	res.Vulnerabilities = vulns
}

type tcpScanOptions struct {
	crawl     bool
	tlsEnum   bool
	tlsVerify bool
}

func scanTCPPort(
	ctx context.Context,
	ip string,
	port int,
	hostname string,
	cdn string,
	cfg *config.Config,
	opts tcpScanOptions,
	asn string,
	org string,
	ptr string,
	kubernetes []scanner.KubernetesOrigin,
) *scanner.ScanResult {
	if !scanner.IsTCPPortOpen(ctx, ip, port, cfg.Scan.Timeout) {
		return nil
	}

	fp := scanner.Fingerprint(ip, port, cfg.Scan.Timeout)

	service := ""
	version := ""
	protocol := "tcp"
	banner := ""
	var metadata []byte

	if fp != nil {
		if fp.Service != "" {
			service = fp.Service
		}
		if fp.Version != "" {
			version = fp.Version
		}
		if fp.Transport != "" {
			protocol = fp.Transport
		}
		metadata = fp.Metadata
	}

	if service == "" || service == "unknown" {
		svc := scanner.DetectServiceContext(ctx, ip, port, cfg.Scan.Timeout)
		if svc.Name == "closed" {
			return nil
		}
		if service == "" || service == "unknown" {
			service = svc.Name
		}
		version = svc.Version
		banner = svc.Banner
	}
	if service == "" {
		service = "unknown"
	}

	likelyTLS := port == 443 || port == 8443 || port == 4443
	if fp != nil && fp.TLS {
		likelyTLS = true
	}
	var tlsResult *scanner.TLSResult
	if likelyTLS {
		tlsResult = scanner.InspectTLS(ctx, ip, hostname, port, cfg.Scan.Timeout, opts.tlsVerify)
	}
	hasTLS := tlsResult != nil || likelyTLS

	var endpoints []scanner.CrawlResult
	var appFP *scanner.AppFingerprint
	if scanner.IsHTTPService(service, port, hasTLS) {
		appFP = scanner.FingerprintHTTP(ctx, scanner.HTTPScheme(hasTLS), ip, hostname, port, cfg.Scan.Timeout, opts.tlsVerify)
	}
	if opts.crawl && scanner.IsHTTPService(service, port, hasTLS) {
		var crawlFP *scanner.AppFingerprint
		endpoints, crawlFP = scanner.Crawl(ctx, scanner.HTTPScheme(hasTLS), ip, hostname, port, cfg.Scan.CrawlDepth, cfg.Scan.Timeout, 100*time.Millisecond, opts.tlsVerify)
		appFP = scanner.MergeAppFingerprints(appFP, crawlFP)
	}
	var products []scanner.ProductFingerprint
	if appFP != nil {
		products = scanner.MergeProductFingerprints(products, appFP.Products)
	}
	products = scanner.MergeProductFingerprints(products, scanner.DetectServiceProducts(service, version, banner, metadata, port, protocol))

	var secHeaders []scanner.HeaderFinding
	if scanner.IsHTTPService(service, port, hasTLS) {
		secHeaders = scanner.InspectHeaders(ctx, scanner.HTTPScheme(hasTLS), ip, hostname, port, cfg.Scan.Timeout, opts.tlsVerify)
	}

	var tlsEnum *scanner.TLSEnum
	if opts.tlsEnum && hasTLS {
		tlsEnum = scanner.EnumerateTLS(ctx, ip, hostname, port, cfg.Scan.Timeout, opts.tlsVerify)
	}

	return &scanner.ScanResult{
		Host:            ip,
		Port:            port,
		Protocol:        protocol,
		Service:         service,
		Version:         version,
		Banner:          banner,
		CDN:             cdn,
		TLS:             tlsResult,
		Metadata:        metadata,
		Endpoints:       endpoints,
		App:             appFP,
		Products:        products,
		SecurityHeaders: secHeaders,
		TLSEnum:         tlsEnum,
		Hostname:        hostname,
		PTR:             ptr,
		ASN:             asn,
		Org:             org,
		Kubernetes:      append([]scanner.KubernetesOrigin(nil), kubernetes...),
	}
}

func displayHost(ip, hostname string) string {
	if hostname == "" || hostname == ip {
		return ip
	}
	return hostname + " (" + ip + ")"
}

func formatKubernetesOrigin(origin scanner.KubernetesOrigin) string {
	parts := make([]string, 0, 4)
	if origin.Kind != "" {
		parts = append(parts, origin.Kind)
	}
	if origin.Namespace != "" && origin.Name != "" {
		parts = append(parts, origin.Namespace+"/"+origin.Name)
	} else if origin.Name != "" {
		parts = append(parts, origin.Name)
	}
	if origin.Cluster != "" {
		parts = append(parts, "cluster="+origin.Cluster)
	}
	if origin.Exposure != "" {
		parts = append(parts, "exposure="+origin.Exposure)
	}
	return strings.Join(parts, " ")
}

func mergeKubernetesOrigins(base, extra []scanner.KubernetesOrigin) []scanner.KubernetesOrigin {
	if len(extra) == 0 {
		return base
	}
	seen := make(map[string]struct{}, len(base)+len(extra))
	out := make([]scanner.KubernetesOrigin, 0, len(base)+len(extra))
	for _, origin := range base {
		key := kubernetesOriginKey(origin)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, origin)
	}
	for _, origin := range extra {
		key := kubernetesOriginKey(origin)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, origin)
	}
	sort.Slice(out, func(i, j int) bool {
		return kubernetesOriginKey(out[i]) < kubernetesOriginKey(out[j])
	})
	return out
}

func kubernetesOriginKey(origin scanner.KubernetesOrigin) string {
	return strings.Join([]string{
		origin.Cluster,
		origin.Context,
		origin.Namespace,
		origin.Kind,
		origin.Name,
		origin.Exposure,
	}, "|")
}

func headerInspectionEligible(res scanner.ScanResult) (bool, int) {
	if len(res.Metadata) == 0 {
		return true, 0
	}

	var meta struct {
		StatusCode int `json:"statusCode"`
	}
	if err := json.Unmarshal(res.Metadata, &meta); err != nil || meta.StatusCode == 0 {
		return true, 0
	}
	if meta.StatusCode >= 200 && meta.StatusCode < 400 {
		return true, meta.StatusCode
	}
	return false, meta.StatusCode
}

func displaySecurityHeaderFindings(res scanner.ScanResult) []scanner.HeaderFinding {
	findings := make([]scanner.HeaderFinding, 0, len(res.SecurityHeaders))
	for _, finding := range res.SecurityHeaders {
		if suppressPrettyHeaderFinding(res, finding) {
			continue
		}
		findings = append(findings, finding)
	}
	return findings
}

func discoveryOutputTargets(allTargets, selectedTargets []string, deltaOnly bool) []string {
	if deltaOnly {
		return selectedTargets
	}
	return allTargets
}

func profileOrDefault(profile string) string {
	if strings.TrimSpace(profile) == "" {
		if envProfile := strings.TrimSpace(os.Getenv("AWS_PROFILE")); envProfile != "" {
			return envProfile
		}
		return "default"
	}
	return profile
}

func suppressPrettyHeaderFinding(res scanner.ScanResult, finding scanner.HeaderFinding) bool {
	if finding.Header != "HTTP Probe" || !strings.EqualFold(finding.Severity, "LOW") {
		return false
	}

	host := strings.ToLower(strings.TrimSpace(res.Hostname))
	version := strings.ToLower(strings.TrimSpace(res.Version))
	detail := strings.ToLower(finding.Detail)

	if strings.Contains(host, ".internal.") || strings.HasPrefix(version, "awselb/") {
		return strings.Contains(detail, "connection reset") ||
			strings.Contains(detail, "context deadline exceeded") ||
			strings.Contains(detail, "client.timeout exceeded")
	}

	return false
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

func shouldStoreResults(jsonlWriter *output.JSONLWriter, analyze bool, prettyMode bool, scanCtx *scanner.ScanContext, togetherAPIKey string) bool {
	if jsonlWriter == nil || analyze || scanCtx != nil {
		return true
	}
	return prettyMode && strings.TrimSpace(togetherAPIKey) != ""
}

func isTransientAPIValidationError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "context deadline exceeded") ||
		strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "temporary") ||
		strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such host")
}

func summarizeAnalysisError(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "402 Payment Required"):
		return "Together API billing or credit limit issue"
	case strings.Contains(msg, "401"):
		return "Together API authentication failed"
	case strings.Contains(msg, "403"):
		return "Together API access denied"
	case strings.Contains(msg, "429"):
		return "Together API rate limited the request"
	default:
		return "Together AI request failed"
	}
}

func enforceScanGuardrails(targetCount, portCount int, cfg *config.Config) error {
	if cfg.Scan.MaxTargets > 0 && targetCount > cfg.Scan.MaxTargets {
		return fmt.Errorf("target count %d exceeds max_targets %d", targetCount, cfg.Scan.MaxTargets)
	}
	if cfg.Scan.MaxPortsHost > 0 && portCount > cfg.Scan.MaxPortsHost {
		return fmt.Errorf("ports per target %d exceeds max_ports_per_target %d", portCount, cfg.Scan.MaxPortsHost)
	}
	return nil
}

func scanMode(domainMode bool, cloudflareMode bool, awsMode bool, kubernetesMode bool) string {
	switch {
	case domainMode && cloudflareMode && awsMode && kubernetesMode:
		return "aws+cloudflare+domain+kubernetes"
	case domainMode && cloudflareMode && awsMode:
		return "aws+cloudflare+domain"
	case domainMode && awsMode && kubernetesMode:
		return "aws+domain+kubernetes"
	case domainMode && cloudflareMode && kubernetesMode:
		return "cloudflare+domain+kubernetes"
	case cloudflareMode && awsMode && kubernetesMode:
		return "aws+cloudflare+kubernetes"
	case domainMode && cloudflareMode:
		return "cloudflare+domain"
	case domainMode && awsMode:
		return "aws+domain"
	case domainMode && kubernetesMode:
		return "domain+kubernetes"
	case cloudflareMode && awsMode:
		return "aws+cloudflare"
	case awsMode && kubernetesMode:
		return "aws+kubernetes"
	case cloudflareMode && kubernetesMode:
		return "cloudflare+kubernetes"
	case awsMode:
		return "aws"
	case cloudflareMode:
		return "cloudflare"
	case kubernetesMode:
		return "kubernetes"
	case domainMode:
		return "domain"
	default:
		return "target"
	}
}

type scanMetadataInput struct {
	mode            string
	inputTargets    int
	resolvedTargets int
	aliveTargets    int
	portsPerTarget  int
	portsScheduled  int
	portsScanned    int64
	servicesFound   int64
	rateLimit       int
	workers         int
	maxHostConns    int
	guardMaxTargets int
	guardMaxPorts   int
	guardMaxDur     time.Duration
	dnsStats        dns.DNSStats
}

func buildScanMetadata(startedAt, completedAt time.Time, runErr error, in scanMetadataInput) output.ScanMetadata {
	metadata := output.ScanMetadata{
		StartedAt:       startedAt.Format(time.RFC3339),
		CompletedAt:     completedAt.Format(time.RFC3339),
		DurationMS:      completedAt.Sub(startedAt).Milliseconds(),
		Mode:            in.mode,
		InputTargets:    in.inputTargets,
		ResolvedTargets: in.resolvedTargets,
		AliveTargets:    in.aliveTargets,
		PortsPerTarget:  in.portsPerTarget,
		PortsScheduled:  in.portsScheduled,
		PortsScanned:    in.portsScanned,
		ServicesFound:   in.servicesFound,
		RateLimit:       in.rateLimit,
		Workers:         in.workers,
		MaxHostConns:    in.maxHostConns,
		Guardrails: output.GuardrailsMetadata{
			MaxTargets:        in.guardMaxTargets,
			MaxPortsPerTarget: in.guardMaxPorts,
			MaxDuration:       in.guardMaxDur.String(),
		},
		DNS: output.DNSMetadata{
			Lookups:          in.dnsStats.Lookups,
			CacheHits:        in.dnsStats.CacheHits,
			CacheMisses:      in.dnsStats.CacheMisses,
			PrimaryFailures:  in.dnsStats.PrimaryFailures,
			FallbackAttempts: in.dnsStats.FallbackAttempts,
			FallbackSuccess:  in.dnsStats.FallbackSuccess,
			LookupFailures:   in.dnsStats.LookupFailures,
		},
	}
	if runErr != nil {
		metadata.Cancelled = true
		metadata.CancelReason = runErr.Error()
	}
	return metadata
}

func writeScanMetadata(outputDir string, metadata output.ScanMetadata) {
	path, err := output.WriteScanMetadata(outputDir, metadata)
	if err != nil {
		slog.Warn("failed to write scan metadata", "err", err)
		return
	}
	if path != "" {
		slog.Info("scan metadata written", "path", path)
	}
}
