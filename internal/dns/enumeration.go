package dns

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var commonSubdomains = []string{
	"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "webdisk",
	"ns2", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap", "test",
	"ns", "blog", "pop3", "dev", "www2", "admin", "store", "dns1", "dns2",
	"mail2", "new", "mysql", "old", "lists", "support", "mobile", "mx", "demo",
	"ash", "blog2", "mx1", "chat", "dns", "www3", "git", "stats", "ns3", "wiki",
	"vpn", "mxs", "mx2", "sec", "vps", "mail3", "ns4", "app", "irc", "relay",
	"logs", "mx0", "git2", "sftp", " ftps", "ssh", "git3", "corp", "nas", "proxy",
	"redis", "sync", "edge", "sync2", "db", "manage", "git1", "stage", "svn",
	"git4", "api", "api2", "api3", "jira", "test2", "beta", "backup", "owa",
	"git5", "ns5", "ns6", "ns7", "ns8", "ns9", "ns10", "ns11", "ns12", "ns13",
	"ns14", "ns15", "v2", "beta2", "test3", "web1", "web2", "web3", "web4",
	"server", "server1", "server2", "server3", "cdn", "cdn2", "static", "files",
	"download", "download2", "upload", "upload2", "cdn3", "assets", "img", "images",
	"img2", "static2", "media", "media2", "files2", "docs", "docs2", "public",
	"private", "crm", "erp", "helpdesk", "portal", "web", "portal2", "shop",
	"store2", "mall", "pay", "payment", "checkout", "cart", "orders", "billing",
	"account", "accounts", "secure", "login", "sso", "auth", "oauth", "token",
	"idp", "ldap", "admin2", "manager", "manage2", "hr", "intranet", "internal",
	"dev2", "staging", "staging2", "prod", "production", "cloud", "cloud2",
	"aws", "azure", "gcp", "kubernetes", "k8s", "docker", "registry", "jenkins",
	"ci", "cd", " pipelines", "build", "deploy", "sonar", "nexus", "artifactory",
	"grafana", "prometheus", "kibana", "logs2", "elasticsearch", "monitor",
	"monitoring", "alert", "alerts", "metrics", "stats2", "analytics", "data",
	"data2", "warehouse", "etl", "spark", "hadoop", "kafka", "rabbitmq", "nats",
	"grpc", "websocket", "realtime", "socket", "push", "notification", "notify",
	"mailer", "smtp2", "smtp3", "mta", "incoming", "outgoing", "filters", "spam",
	" quarantine", "archiver", "archive", "webhook", "hooks", "hook", "bot", "bots",
	"chatbot", "ai", "ml", "ml2", "model", "models", "training", "inference",
	"lambda", "function", "functions", "faas", "serverless", "edge2", "cdn4",
	"global", "regional", "east", "west", "north", "south", "us", "us2", "eu",
	"eu2", "ap", "ap2", "au", "au2", "jp", "jp2", "sg", "sg2", "in", "in2",
	"br", "br2", "ca", "ca2", "uk", "uk2", "de", "de2", "fr", "fr2", "es", "es2",
	"it", "it2", "nl", "nl2", "se", "se2", "no", "no2", "fi", "fi2", "dk", "dk2",
	"pl", "pl2", "ru", "ru2", "cn", "cn2", "kr", "kr2", "tw", "tw2", "hk", "hk2",
	"sgp", "sgp2", "id", "id2", "my", "my2", "th", "th2", "vn", "vn2", "ph",
	"ph2", "nz", "nz2", "za", "za2", "eg", "eg2", "sa", "sa2", "ae", "ae2",
	"il", "il2", "ng", "ng2", "ke", "ke2", "ma", "ma2", "gh", "gh2", "tz",
	"tz2", "et", "et2", "rw", "rw2", "ug", "ug2", "zm", "zm2", "zw", "zw2",
	"mw", "mw2", "mz", "mz2", "bw", "bw2", "na", "na2", "sz", "sz2", "ls", "ls2",
	"cd", "cd2", "cg", "cg2", "ga", "ga2", "gq", "gq2", "cm", "cm2", "sn", "sn2",
	"ci", "ci2", "bf", "bf2", "ml", "ml2", "ne", "ne2", "tg", "tg2", "bj", "bj2",
}

type EnumerationResult struct {
	Hostname string
	IP       net.IP
	Type     string
}

type Enumerator struct {
	timeout time.Duration
	workers int
}

func NewEnumerator(timeout time.Duration, workers int) *Enumerator {
	return &Enumerator{
		timeout: timeout,
		workers: workers,
	}
}

func (e *Enumerator) Enumerate(domain string) ([]EnumerationResult, error) {
	var results []EnumerationResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)

	if !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	resolver := &net.Resolver{
		PreferGo: true,
	}

	checked := make(map[string]bool)
	var checkedMu sync.Mutex

	tryLookup := func(host string) {
		checkedMu.Lock()
		if checked[host] {
			checkedMu.Unlock()
			return
		}
		checked[host] = true
		checkedMu.Unlock()

		fullHost := host + "." + domain
		ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
		defer cancel()
		addrs, err := resolver.LookupIPAddr(ctx, fullHost)
		if err != nil {
			return
		}

		for _, addr := range addrs {
			mu.Lock()
			results = append(results, EnumerationResult{
				Hostname: fullHost,
				IP:       addr.IP,
				Type:     "subdomain",
			})
			mu.Unlock()
		}
	}

	processQueue := make(chan string, e.workers)
	for i := 0; i < e.workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range processQueue {
				tryLookup(host)
			}
		}()
	}

	for _, sub := range commonSubdomains {
		processQueue <- sub
	}
	close(processQueue)
	wg.Wait()

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	addrs, err := resolver.LookupIPAddr(ctx, domain)
	if err == nil && len(addrs) > 0 {
		for _, addr := range addrs {
			mu.Lock()
			results = append(results, EnumerationResult{
				Hostname: domain,
				IP:       addr.IP,
				Type:     "apex",
			})
			mu.Unlock()
		}
	}

	results = e.reverseSweep(domain, results)

	return results, nil
}

func (e *Enumerator) reverseSweep(domain string, results []EnumerationResult) []EnumerationResult {
	var mu sync.Mutex

	resolver := &net.Resolver{
		PreferGo: true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()

	nameservers, err := resolver.LookupNS(ctx, domain)
	if err != nil || len(nameservers) == 0 {
		return results
	}

	var targetNS string
	for _, ns := range nameservers {
		host := strings.TrimSuffix(ns.Host, ".")
		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err == nil && len(addrs) > 0 {
			targetNS = ns.Host
			break
		}
	}

	if targetNS == "" {
		return results
	}

	conn, err := net.DialTimeout("udp", targetNS, e.timeout)
	if err != nil {
		return results
	}
	defer conn.Close()

	axfrQuery := fmt.Sprintf("axfr query for %s", domain)
	conn.Write([]byte(axfrQuery))
	conn.SetReadDeadline(time.Now().Add(e.timeout))

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err == nil && n > 0 {
		response := string(buf[:n])
		if strings.Contains(response, domain) {
			lines := strings.Split(response, "\n")
			for _, line := range lines {
				if strings.Contains(line, "A") || strings.Contains(line, "AAAA") {
					parts := strings.Fields(line)
					for _, part := range parts {
						if ip := net.ParseIP(part); ip != nil {
							mu.Lock()
							results = append(results, EnumerationResult{
								Hostname: domain,
								IP:       ip,
								Type:     "zone_transfer",
							})
							mu.Unlock()
						}
					}
				}
			}
		}
	}

	return results
}

func ResolveHostname(host string) ([]net.IP, error) {
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	return ips, nil
}

func GetARecords(domain string) ([]net.IP, error) {
	return ResolveHostname(domain)
}

func GetNSRecords(domain string) ([]string, error) {
	resolver := &net.Resolver{PreferGo: true}
	nsRecords, err := resolver.LookupNS(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	var nss []string
	for _, ns := range nsRecords {
		nss = append(nss, strings.TrimSuffix(ns.Host, "."))
	}
	return nss, nil
}

func GetMXRecords(domain string) ([]string, error) {
	resolver := &net.Resolver{PreferGo: true}
	mxRecords, err := resolver.LookupMX(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	var mxs []string
	for _, mx := range mxRecords {
		mxs = append(mxs, strings.TrimSuffix(mx.Host, "."))
	}
	return mxs, nil
}

func GetTXTRecords(domain string) ([]string, error) {
	resolver := &net.Resolver{PreferGo: true}
	txtRecords, err := resolver.LookupTXT(context.Background(), domain)
	if err != nil {
		return nil, err
	}
	return txtRecords, nil
}

func GetCNAMERecords(alias string) (string, error) {
	resolver := &net.Resolver{PreferGo: true}
	cname, err := resolver.LookupCNAME(context.Background(), alias)
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(cname, "."), nil
}
