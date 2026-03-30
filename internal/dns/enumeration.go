package dns

import (
	"bufio"
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

var defaultSubdomains = []string{
	"www", "mail", "ftp", "webmail", "smtp", "pop", "ns1", "ns2", "cpanel",
	"whm", "autodiscover", "autoconfig", "m", "imap", "test", "ns", "blog",
	"pop3", "dev", "www2", "admin", "store", "dns1", "dns2", "mail2", "new",
	"mysql", "old", "lists", "support", "mobile", "mx", "demo", "blog2",
	"mx1", "chat", "dns", "www3", "git", "stats", "ns3", "wiki", "vpn",
	"mx2", "sec", "vps", "mail3", "ns4", "app", "irc", "relay", "logs",
	"sftp", "ftps", "ssh", "corp", "nas", "proxy", "redis", "sync", "edge",
	"db", "manage", "stage", "svn", "api", "api2", "api3", "jira", "test2",
	"beta", "backup", "owa", "v2", "web1", "web2", "web3", "web4", "server",
	"server1", "server2", "server3", "cdn", "cdn2", "static", "files",
	"download", "upload", "assets", "img", "images", "static2", "media",
	"docs", "public", "private", "crm", "erp", "helpdesk", "portal", "web",
	"shop", "pay", "payment", "checkout", "billing", "account", "accounts",
	"secure", "login", "sso", "auth", "oauth", "token", "ldap", "admin2",
	"manager", "hr", "intranet", "internal", "dev2", "staging", "prod",
	"production", "cloud", "aws", "azure", "gcp", "kubernetes", "k8s",
	"docker", "registry", "jenkins", "ci", "grafana", "prometheus", "kibana",
	"elasticsearch", "monitor", "monitoring", "alerts", "metrics", "analytics",
	"data", "kafka", "rabbitmq", "api2", "webhook", "archive", "bot",
}

type EnumerationResult struct {
	Hostname string
	IP       net.IP
	Type     string
}

type Enumerator struct {
	timeout  time.Duration
	workers  int
	resolver *net.Resolver
}

func NewEnumerator(timeout time.Duration, workers int) *Enumerator {
	return &Enumerator{
		timeout:  timeout,
		workers:  workers,
		resolver: &net.Resolver{PreferGo: true},
	}
}

func NewEnumeratorWithResolver(timeout time.Duration, workers int, resolverAddr string) *Enumerator {
	resolverAddr = normalizeResolverAddr(resolverAddr)
	if resolverAddr == "" || resolverAddr == "system" {
		return NewEnumerator(timeout, workers)
	}
	return &Enumerator{
		timeout: timeout,
		workers: workers,
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: timeout}
				return d.DialContext(ctx, "udp", resolverAddr)
			},
		},
	}
}

func LoadWordlist(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var words []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		w := strings.TrimSpace(s.Text())
		if w != "" {
			words = append(words, w)
		}
	}
	return words, s.Err()
}

func (e *Enumerator) Enumerate(domain string) ([]EnumerationResult, error) {
	return e.EnumerateWithWordlist(context.Background(), domain, defaultSubdomains)
}

func (e *Enumerator) EnumerateWithWordlist(ctx context.Context, domain string, wordlist []string) ([]EnumerationResult, error) {
	var results []EnumerationResult
	var mu sync.Mutex
	var wg sync.WaitGroup

	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)

	if !strings.Contains(domain, ".") {
		return nil, fmt.Errorf("invalid domain: %s", domain)
	}

	wildcardIPs := e.detectWildcard(ctx, domain)

	checked := make(map[string]bool)
	var checkedMu sync.Mutex

	tryLookup := func(ctx context.Context, host string) {
		checkedMu.Lock()
		if checked[host] {
			checkedMu.Unlock()
			return
		}
		checked[host] = true
		checkedMu.Unlock()

		fullHost := host + "." + domain
		lCtx, cancel := context.WithTimeout(ctx, e.timeout)
		defer cancel()
		addrs, err := e.resolver.LookupIPAddr(lCtx, fullHost)
		if err != nil {
			return
		}

		for _, addr := range addrs {
			if wildcardIPs[addr.IP.String()] {
				continue
			}
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
				tryLookup(ctx, host)
			}
		}()
	}

	for _, sub := range wordlist {
		processQueue <- sub
	}
	close(processQueue)
	wg.Wait()

	apexCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()
	addrs, err := e.resolver.LookupIPAddr(apexCtx, domain)
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

	return results, nil
}

func (e *Enumerator) detectWildcard(ctx context.Context, domain string) map[string]bool {
	wildcardIPs := make(map[string]bool)
	for i := 0; i < 3; i++ {
		random := fmt.Sprintf("%s-wildcard-check-%d.%s", randomString(12), i, domain)
		wCtx, cancel := context.WithTimeout(ctx, e.timeout)
		addrs, err := e.resolver.LookupIPAddr(wCtx, random)
		cancel()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			wildcardIPs[addr.IP.String()] = true
		}
	}
	return wildcardIPs
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	b := make([]byte, n)
	for i := range b {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(letters))))
		if err != nil {
			b[i] = letters[0]
			continue
		}
		b[i] = letters[idx.Int64()]
	}
	return string(b)
}

const dnsTimeout = 10 * time.Second

func GetNSRecords(domain string) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true}
	nsRecords, err := resolver.LookupNS(ctx, domain)
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
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true}
	mxRecords, err := resolver.LookupMX(ctx, domain)
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
	ctx, cancel := context.WithTimeout(context.Background(), dnsTimeout)
	defer cancel()
	resolver := &net.Resolver{PreferGo: true}
	txtRecords, err := resolver.LookupTXT(ctx, domain)
	if err != nil {
		return nil, err
	}
	return txtRecords, nil
}
