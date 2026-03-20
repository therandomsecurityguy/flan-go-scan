package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/html"
)

type CrawlResult struct {
	Path        string `json:"path"`
	StatusCode  int    `json:"status_code"`
	ContentType string `json:"content_type,omitempty"`
	Title       string `json:"title,omitempty"`
	RedirectTo  string `json:"redirect_to,omitempty"`
}

type AppFingerprint struct {
	Server    string               `json:"server,omitempty"`
	PoweredBy string               `json:"powered_by,omitempty"`
	Generator string               `json:"generator,omitempty"`
	Apps      []string             `json:"apps,omitempty"`
	Products  []ProductFingerprint `json:"products,omitempty"`
}

var sensitivePaths = []string{
	"/.env", "/.env.local", "/.env.production", "/.env.backup",
	"/.git/HEAD", "/.git/config",
	"/config.php.bak", "/wp-config.php.bak", "/configuration.php.bak",
	"/.htaccess", "/web.config",
	"/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
	"/readme.html", "/README.md", "/CHANGELOG.txt", "/LICENSE.txt",
	"/admin", "/admin/", "/login", "/signin", "/dashboard",
	"/api", "/api/v1", "/api/v2", "/api/docs",
	"/swagger", "/swagger-ui", "/swagger-ui.html", "/swagger.json", "/openapi.json",
	"/graphql", "/graphiql",
	"/version", "/readyz", "/livez", "/healthz", "/api", "/apis", "/openapi/v2", "/openapi/v3",
	"/debug/pprof", "/__debug__/",
	"/wp-login.php", "/wp-admin/", "/wp-content/", "/wp-includes/", "/xmlrpc.php", "/wp-json/",
	"/administrator/", "/components/", "/templates/",
	"/user/login", "/sites/default/", "/core/misc/",
	"/typo3/", "/typo3temp/", "/typo3conf/",
	"/magento/", "/skin/frontend/", "/index.php/admin/",
	"/ghost/", "/ghost/signin",
	"/umbraco/", "/umbraco/backoffice/",
	"/wiki/", "/w/index.php",
	"/phpbb/", "/forum/", "/viewtopic.php",
	"/moodle/", "/course/view.php",
	"/concrete/", "/application/",
	"/elmah.axd", "/trace.axd", "/WebResource.axd", "/ScriptResource.axd",
	"/phpmyadmin/", "/phpmyadmin/index.php", "/pma/",
	"/adminer/", "/adminer.php", "/pgadmin/", "/pgadmin4/",
	"/actuator/", "/actuator/health", "/actuator/info", "/actuator/env",
	"/_debugbar/", "/laravel/",
	"/rails/info/", "/rails/info/properties",
	"/django-admin/",
	"/cfide/", "/CFIDE/administrator/",
	"/jenkins/", "/jenkins/view/all/",
	"/gitlab/", "/users/sign_in",
	"/gitea/", "/user/sign_in",
	"/bitbucket/",
	"/grafana/", "/grafana/login",
	"/kibana/", "/app/kibana",
	"/prometheus/", "/metrics", "/-/healthy",
	"/netdata/", "/netdata/index.html",
	"/zabbix/", "/nagios/",
	"/portainer/", "/portainer/api/",
	"/rancher/", "/dashboard/",
	"/traefik/", "/traefik/dashboard/",
	"/auth/admin/", "/auth/realms/", "/keycloak/",
	"/vault/", "/v1/sys/health",
	"/consul/", "/v1/agent/self",
	"/nexus/", "/repository/",
	"/artifactory/", "/jfrog/",
	"/sonarqube/", "/sonar/",
	"/harbor/",
	"/roundcube/", "/webmail/", "/zimbra/", "/owa/",
	"/cpanel", "/whm", "/plesk/", "/directadmin/",
	"/session_login.cgi",
	"/remote/login", "/remote/fgt_lang", "/+CSCOE+/logon.html", "/my.policy", "/tmui/login.jsp",
	"/ui/", "/login.html", "/app/rest/server",
	"/_cat/health", "/_nodes", "/solr/",
}

var pathTech = map[string]string{
	"/wp-login.php":          "WordPress",
	"/wp-admin/":             "WordPress",
	"/wp-content/":           "WordPress",
	"/wp-includes/":          "WordPress",
	"/xmlrpc.php":            "WordPress",
	"/wp-json/":              "WordPress",
	"/wp-config.php.bak":     "WordPress",
	"/administrator/":        "Joomla",
	"/components/":           "Joomla",
	"/templates/":            "Joomla",
	"/user/login":            "Drupal",
	"/sites/default/":        "Drupal",
	"/core/misc/":            "Drupal",
	"/CHANGELOG.txt":         "Drupal",
	"/typo3/":                "TYPO3",
	"/typo3temp/":            "TYPO3",
	"/typo3conf/":            "TYPO3",
	"/magento/":              "Magento",
	"/skin/frontend/":        "Magento",
	"/ghost/":                "Ghost",
	"/ghost/signin":          "Ghost",
	"/umbraco/":              "Umbraco",
	"/umbraco/backoffice/":   "Umbraco",
	"/wiki/":                 "MediaWiki",
	"/w/index.php":           "MediaWiki",
	"/phpbb/":                "phpBB",
	"/moodle/":               "Moodle",
	"/course/view.php":       "Moodle",
	"/concrete/":             "Concrete CMS",
	"/elmah.axd":             "ASP.NET",
	"/trace.axd":             "ASP.NET",
	"/WebResource.axd":       "ASP.NET",
	"/ScriptResource.axd":    "ASP.NET",
	"/phpmyadmin/":           "phpMyAdmin",
	"/phpmyadmin/index.php":  "phpMyAdmin",
	"/pma/":                  "phpMyAdmin",
	"/adminer/":              "Adminer",
	"/adminer.php":           "Adminer",
	"/pgadmin/":              "pgAdmin",
	"/pgadmin4/":             "pgAdmin",
	"/actuator/":             "Spring Boot",
	"/actuator/health":       "Spring Boot",
	"/actuator/info":         "Spring Boot",
	"/actuator/env":          "Spring Boot",
	"/_debugbar/":            "Laravel",
	"/laravel/":              "Laravel",
	"/rails/info/":           "Ruby on Rails",
	"/rails/info/properties": "Ruby on Rails",
	"/django-admin/":         "Django",
	"/__debug__/":            "Django",
	"/cfide/":                "ColdFusion",
	"/CFIDE/administrator/":  "ColdFusion",
	"/jenkins/":              "Jenkins",
	"/jenkins/view/all/":     "Jenkins",
	"/users/sign_in":         "GitLab",
	"/gitlab/":               "GitLab",
	"/user/sign_in":          "Gitea",
	"/grafana/":              "Grafana",
	"/grafana/login":         "Grafana",
	"/kibana/":               "Kibana",
	"/app/kibana":            "Kibana",
	"/prometheus/":           "Prometheus",
	"/metrics":               "Prometheus/metrics",
	"/portainer/":            "Portainer",
	"/traefik/":              "Traefik",
	"/auth/admin/":           "Keycloak",
	"/auth/realms/":          "Keycloak",
	"/keycloak/":             "Keycloak",
	"/vault/":                "HashiCorp Vault",
	"/v1/sys/health":         "HashiCorp Vault",
	"/v1/agent/self":         "HashiCorp Consul",
	"/nexus/":                "Nexus Repository",
	"/repository/":           "Nexus Repository",
	"/artifactory/":          "JFrog Artifactory",
	"/sonarqube/":            "SonarQube",
	"/sonar/":                "SonarQube",
	"/harbor/":               "Harbor Registry",
	"/roundcube/":            "Roundcube Webmail",
	"/webmail/":              "Webmail",
	"/zimbra/":               "Zimbra",
	"/owa/":                  "Outlook Web Access",
	"/cpanel":                "cPanel",
	"/whm":                   "WHM",
	"/plesk/":                "Plesk",
	"/directadmin/":          "DirectAdmin",
	"/session_login.cgi":     "Webmin",
	"/_cat/health":           "Elasticsearch",
	"/_nodes":                "Elasticsearch",
	"/solr/":                 "Apache Solr",
	"/netdata/":              "Netdata",
	"/zabbix/":               "Zabbix",
	"/nagios/":               "Nagios",
}

var cookieTech = map[string]string{
	"wordpress_":   "WordPress",
	"wp-settings":  "WordPress",
	"wp_":          "WordPress",
	"phpsessid":    "PHP",
	"jsessionid":   "Java/Tomcat",
	"asp.net_":     "ASP.NET",
	"laravel_":     "Laravel",
	"ci_session":   "CodeIgniter",
	"drupal_":      "Drupal",
	"symfony":      "Symfony",
	"yii":          "Yii Framework",
	"csrftoken":    "Django",
	"rack.session": "Ruby/Rack",
	"connect.sid":  "Node.js/Express",
}

var productProbePaths = []string{
	"/",
	"/graphql",
	"/version",
	"/api",
	"/apis",
	"/readyz",
	"/livez",
	"/healthz",
	"/openapi/v2",
	"/openapi/v3",
	"/v1/sys/health",
	"/v1/agent/self",
	"/-/healthy",
	"/_cat/health",
	"/_nodes",
	"/grafana/login",
	"/artifactory/",
	"/jfrog/",
	"/remote/login",
	"/tmui/login.jsp",
	"/my.policy",
	"/+CSCOE+/logon.html",
	"/login.html",
	"/app/rest/server",
	"/ui/",
}

func Crawl(ctx context.Context, scheme, ip, hostname string, port int, maxDepth int, timeout time.Duration, reqDelay time.Duration, verifyTLS bool) ([]CrawlResult, *AppFingerprint) {
	return crawlHTTP(ctx, scheme, ip, hostname, port, maxDepth, timeout, reqDelay, verifyTLS, true)
}

func FingerprintHTTP(ctx context.Context, scheme, ip, hostname string, port int, timeout time.Duration, verifyTLS bool) *AppFingerprint {
	_, fp := crawlHTTP(ctx, scheme, ip, hostname, port, 0, timeout, 0, verifyTLS, false)
	return fp
}

func MergeAppFingerprints(base, extra *AppFingerprint) *AppFingerprint {
	if base == nil {
		return extra
	}
	if extra == nil {
		return base
	}
	if base.Server == "" {
		base.Server = extra.Server
	}
	if base.PoweredBy == "" {
		base.PoweredBy = extra.PoweredBy
	}
	if base.Generator == "" {
		base.Generator = extra.Generator
	}
	appsFound := make(map[string]bool, len(base.Apps))
	for _, app := range base.Apps {
		appsFound[app] = true
	}
	for _, app := range extra.Apps {
		addApp(base, appsFound, app)
	}
	productsFound := make(map[string]string, len(base.Products))
	for _, product := range base.Products {
		productsFound[product.Name] = product.Confidence
	}
	for _, product := range extra.Products {
		addProduct(base, productsFound, product.Name, product.Confidence)
	}
	return base
}

func crawlHTTP(ctx context.Context, scheme, ip, hostname string, port int, maxDepth int, timeout time.Duration, reqDelay time.Duration, verifyTLS bool, followLinks bool) ([]CrawlResult, *AppFingerprint) {
	displayHost := ip
	if strings.Contains(ip, ":") {
		displayHost = "[" + ip + "]"
	}
	base := fmt.Sprintf("%s://%s:%d", scheme, displayHost, port)

	crawlTimeout := timeout * 3
	if crawlTimeout > 8*time.Second {
		crawlTimeout = 8 * time.Second
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: !verifyTLS}
	if hostname != "" && net.ParseIP(hostname) == nil {
		tlsCfg.ServerName = hostname
	}
	transport := &http.Transport{
		TLSClientConfig: tlsCfg,
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Timeout:   crawlTimeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	type entry struct {
		path  string
		depth int
	}

	visited := make(map[string]bool)
	appsFound := make(map[string]bool)
	productsFound := make(map[string]string)
	fp := &AppFingerprint{}
	var results []CrawlResult

	paths := sensitivePaths
	if !followLinks {
		paths = productProbePaths
	}
	queue := make([]entry, 0, len(paths)+1)
	for _, p := range paths {
		queue = append(queue, entry{p, 0})
	}
	if len(paths) == 0 || paths[0] != "/" {
		queue = append(queue, entry{"/", 0})
	}
	head := 0

	var timer *time.Timer
	if reqDelay > 0 {
		timer = time.NewTimer(reqDelay)
		defer timer.Stop()
	}

	for head < len(queue) {
		if ctx.Err() != nil {
			break
		}

		e := queue[head]
		head++

		if visited[e.path] {
			continue
		}
		visited[e.path] = true

		if timer != nil {
			timer.Reset(reqDelay)
			select {
			case <-ctx.Done():
				if appFingerprintEmpty(fp) {
					return results, nil
				}
				return results, fp
			case <-timer.C:
			}
		}

		cr, body := fetchPath(ctx, client, base, hostname, e.path, fp, appsFound, productsFound)
		if cr == nil {
			continue
		}
		results = append(results, *cr)

		if tech, ok := pathTech[e.path]; ok && cr.StatusCode < 404 && !appsFound[tech] {
			fp.Apps = append(fp.Apps, tech)
			appsFound[tech] = true
		}
		if e.path == "/" && body != "" && fp.Generator == "" {
			fp.Generator = extractMeta(body, "generator")
		}

		if e.path == "/robots.txt" && cr.StatusCode == 200 && body != "" {
			for _, disallowed := range parseRobotsTxt(body) {
				if !visited[disallowed] {
					slog.Debug("robots.txt disallow entry added to crawl queue", "path", disallowed)
					queue = append(queue, entry{disallowed, e.depth})
				}
			}
		}

		if followLinks && e.depth < maxDepth && strings.Contains(cr.ContentType, "text/html") && body != "" && cr.StatusCode < 400 {
			for _, link := range extractLinks(body, base) {
				if !visited[link] {
					queue = append(queue, entry{link, e.depth + 1})
				}
			}
		}
	}

	if appFingerprintEmpty(fp) {
		return results, nil
	}
	return results, fp
}

func addApp(fp *AppFingerprint, found map[string]bool, tech string) {
	if tech != "" && !found[tech] {
		fp.Apps = append(fp.Apps, tech)
		found[tech] = true
	}
}

func fetchPath(ctx context.Context, client *http.Client, base, hostname, path string, fp *AppFingerprint, appsFound map[string]bool, productsFound map[string]string) (*CrawlResult, string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", "flan-scanner/1.0")
	if hostname != "" {
		req.Host = hostname
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, ""
	}
	defer resp.Body.Close()

	cr := &CrawlResult{
		Path:        path,
		StatusCode:  resp.StatusCode,
		ContentType: resp.Header.Get("Content-Type"),
	}

	if loc := resp.Header.Get("Location"); loc != "" {
		cr.RedirectTo = loc
	}

	if s := resp.Header.Get("Server"); s != "" && fp.Server == "" {
		fp.Server = s
	}
	if p := resp.Header.Get("X-Powered-By"); p != "" && fp.PoweredBy == "" {
		fp.PoweredBy = p
	}
	if g := resp.Header.Get("X-Generator"); g != "" && fp.Generator == "" {
		fp.Generator = g
	}
	if resp.Header.Get("X-Drupal-Cache") != "" || resp.Header.Get("X-Drupal-Dynamic-Cache") != "" {
		addApp(fp, appsFound, "Drupal")
	}
	if resp.Header.Get("X-Pingback") != "" {
		addApp(fp, appsFound, "WordPress")
	}
	if resp.Header.Get("X-AspNet-Version") != "" || resp.Header.Get("X-AspNetMvc-Version") != "" {
		addApp(fp, appsFound, "ASP.NET")
	}
	if resp.Header.Get("X-CF-Powered-By") != "" {
		addApp(fp, appsFound, "ColdFusion")
	}
	for _, c := range resp.Cookies() {
		lower := strings.ToLower(c.Name)
		for prefix, tech := range cookieTech {
			if strings.HasPrefix(lower, prefix) {
				addApp(fp, appsFound, tech)
				break
			}
		}
	}

	if !strings.Contains(cr.ContentType, "text/") {
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		return cr, ""
	}

	b, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	io.Copy(io.Discard, resp.Body) //nolint:errcheck
	if err != nil {
		return cr, ""
	}
	body := string(b)

	if strings.Contains(cr.ContentType, "text/html") {
		cr.Title = extractTitle(body)
	}
	detectDeeperProduct(path, cr, resp.Header, body, fp, productsFound)

	return cr, body
}

func appFingerprintEmpty(fp *AppFingerprint) bool {
	return fp.Server == "" && fp.PoweredBy == "" && fp.Generator == "" && len(fp.Apps) == 0 && len(fp.Products) == 0
}

func addProduct(fp *AppFingerprint, found map[string]string, name, confidence string) {
	if name == "" {
		return
	}
	current, ok := found[name]
	if ok && productConfidenceRank(current) >= productConfidenceRank(confidence) {
		return
	}
	found[name] = confidence
	for i := range fp.Products {
		if fp.Products[i].Name == name {
			fp.Products[i].Confidence = confidence
			return
		}
	}
	fp.Products = append(fp.Products, ProductFingerprint{Name: name, Confidence: confidence})
}

func productConfidenceRank(confidence string) int {
	switch strings.ToLower(confidence) {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

func detectDeeperProduct(path string, cr *CrawlResult, headers http.Header, body string, fp *AppFingerprint, productsFound map[string]string) {
	server := strings.ToLower(fp.Server)
	poweredBy := strings.ToLower(fp.PoweredBy)
	generator := strings.ToLower(fp.Generator)
	title := strings.ToLower(cr.Title)
	bodyLower := strings.ToLower(body)
	statusOK := cr.StatusCode > 0 && cr.StatusCode < 500

	switch {
	case headers.Get("X-JFrog-Version") != "" || headers.Get("X-Artifactory-Id") != "" || strings.Contains(bodyLower, "artifactory"):
		addProduct(fp, productsFound, "Artifactory", "high")
	case strings.EqualFold(headers.Get("X-Elastic-Product"), "Elasticsearch") || strings.Contains(bodyLower, "\"cluster_name\"") || path == "/_cat/health" || path == "/_nodes":
		addProduct(fp, productsFound, "Elasticsearch", "high")
	case strings.Contains(title, "grafana") || strings.Contains(bodyLower, "grafana") || strings.Contains(path, "/grafana/"):
		addProduct(fp, productsFound, "Grafana", "high")
	case strings.Contains(bodyLower, "hashicorp vault") || strings.Contains(bodyLower, "\"sealed\"") && strings.Contains(path, "/v1/sys/health"):
		addProduct(fp, productsFound, "Vault", "high")
	case strings.Contains(bodyLower, "\"config\"") && strings.Contains(path, "/v1/agent/self") || strings.Contains(bodyLower, "\"datacenter\"") && strings.Contains(bodyLower, "\"revision\""):
		addProduct(fp, productsFound, "Consul", "high")
	case strings.Contains(title, "prometheus") || path == "/-/healthy" || strings.Contains(bodyLower, "prometheus time series collection"):
		addProduct(fp, productsFound, "Prometheus", "high")
	case strings.Contains(server, "fortigate") || strings.Contains(title, "fortigate") || strings.Contains(bodyLower, "fortinet"):
		addProduct(fp, productsFound, "FortiGate", "medium")
	case strings.Contains(server, "big-ip") || strings.Contains(title, "big-ip") || strings.Contains(bodyLower, "f5 networks"):
		addProduct(fp, productsFound, "BigIP", "medium")
	case strings.Contains(title, "cisco") && strings.Contains(bodyLower, "anyconnect") || strings.Contains(bodyLower, "ssl vpn service") && strings.Contains(bodyLower, "cisco"):
		addProduct(fp, productsFound, "AnyConnect", "medium")
	case strings.Contains(title, "teamcity") || headers.Get("TeamCity-Node-Id") != "" || strings.Contains(bodyLower, "teamcity"):
		addProduct(fp, productsFound, "TeamCity", "high")
	case path == "/version" && strings.Contains(bodyLower, "etcdserver") || strings.Contains(bodyLower, "etcdcluster"):
		addProduct(fp, productsFound, "etcd", "high")
	case path == "/version" && strings.Contains(bodyLower, "\"major\"") && strings.Contains(bodyLower, "\"minor\""):
		addProduct(fp, productsFound, "Kubernetes API Server", "high")
		addProduct(fp, productsFound, "Kubernetes", "high")
	case statusOK && (headers.Get("Audit-Id") != "" || headers.Get("X-Kubernetes-Pf-Flowschema-Uid") != "" || headers.Get("X-Kubernetes-Pf-Prioritylevel-Uid") != ""):
		addProduct(fp, productsFound, "Kubernetes API Server", "high")
		addProduct(fp, productsFound, "Kubernetes", "medium")
	case statusOK && (path == "/api" || path == "/apis" || path == "/readyz" || path == "/livez" || path == "/healthz" || path == "/openapi/v2" || path == "/openapi/v3") && strings.Contains(bodyLower, "kubernetes"):
		addProduct(fp, productsFound, "Kubernetes API Server", "medium")
		addProduct(fp, productsFound, "Kubernetes", "medium")
	case strings.Contains(title, "kubernetes dashboard") || strings.Contains(bodyLower, "kubernetes dashboard"):
		addProduct(fp, productsFound, "Kubernetes Dashboard", "high")
		addProduct(fp, productsFound, "Kubernetes", "medium")
	case (path == "/" || path == "/healthz") && (strings.Contains(bodyLower, "default backend - 404") || strings.Contains(bodyLower, "ingress-nginx")):
		addProduct(fp, productsFound, "Kubernetes Ingress", "high")
		addProduct(fp, productsFound, "Kubernetes", "medium")
	case strings.Contains(generator, "grafana"):
		addProduct(fp, productsFound, "Grafana", "medium")
	case strings.Contains(generator, "teamcity"):
		addProduct(fp, productsFound, "TeamCity", "medium")
	case strings.Contains(poweredBy, "artifactory"):
		addProduct(fp, productsFound, "Artifactory", "medium")
	case path == "/graphql" && (strings.Contains(bodyLower, "graphql") || strings.Contains(strings.ToLower(headers.Get("Content-Type")), "graphql")):
		addProduct(fp, productsFound, "GraphQL", "high")
	case strings.Contains(bodyLower, "__schema") || strings.Contains(bodyLower, "must provide query string") || strings.Contains(bodyLower, "graphql"):
		if path == "/" || path == "/graphql" {
			addProduct(fp, productsFound, "GraphQL", "medium")
		}
	}
}

func extractLinks(body, base string) []string {
	baseURL, err := url.Parse(base)
	if err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var links []string

	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.StartTagToken && tt != html.SelfClosingTagToken {
			continue
		}

		tok := z.Token()
		var attrName string
		switch tok.Data {
		case "a", "link":
			attrName = "href"
		case "script", "img":
			attrName = "src"
		case "form":
			attrName = "action"
		default:
			continue
		}

		for _, attr := range tok.Attr {
			if attr.Key != attrName {
				continue
			}
			raw := strings.TrimSpace(attr.Val)
			if raw == "" || strings.HasPrefix(raw, "javascript:") ||
				strings.HasPrefix(raw, "mailto:") ||
				strings.HasPrefix(raw, "data:") ||
				strings.HasPrefix(raw, "#") {
				continue
			}

			u, err := url.Parse(raw)
			if err != nil {
				continue
			}

			resolved := baseURL.ResolveReference(u)
			if !sameHost(resolved, baseURL) {
				continue
			}

			p := resolved.Path
			if p == "" {
				p = "/"
			}
			if !seen[p] {
				seen[p] = true
				links = append(links, p)
			}
		}
	}

	return links
}

func sameHost(a, b *url.URL) bool {
	return normalizeHost(a) == normalizeHost(b)
}

func normalizeHost(u *url.URL) string {
	h := u.Hostname()
	p := u.Port()
	if p == "" {
		return h
	}
	switch {
	case u.Scheme == "http" && p == "80":
		return h
	case u.Scheme == "https" && p == "443":
		return h
	}
	return h + ":" + p
}

func extractTitle(body string) string {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt == html.StartTagToken {
			tok := z.Token()
			if tok.Data == "title" {
				if z.Next() == html.TextToken {
					return strings.TrimSpace(string(z.Text()))
				}
			}
		}
	}
	return ""
}

func extractMeta(body, name string) string {
	z := html.NewTokenizer(strings.NewReader(body))
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		if tt != html.SelfClosingTagToken && tt != html.StartTagToken {
			continue
		}
		tok := z.Token()
		if tok.Data != "meta" {
			continue
		}
		var metaName, content string
		for _, attr := range tok.Attr {
			switch attr.Key {
			case "name":
				metaName = attr.Val
			case "content":
				content = attr.Val
			}
		}
		if strings.EqualFold(metaName, name) && content != "" {
			return content
		}
	}
	return ""
}

func parseRobotsTxt(body string) []string {
	var paths []string
	sc := bufio.NewScanner(strings.NewReader(body))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "disallow:") {
			path := strings.TrimSpace(line[len("disallow:"):])
			if path != "" && path != "/" && strings.HasPrefix(path, "/") {
				paths = append(paths, path)
			}
		}
	}
	return paths
}

func IsHTTPService(service string, port int, tls bool) bool {
	svc := strings.ToLower(service)
	if strings.Contains(svc, "http") {
		return true
	}
	switch port {
	case 80, 8080, 8000, 8888, 3000:
		return true
	case 443, 8443, 4443:
		return tls || service == ""
	}
	return false
}

func HTTPScheme(tls bool) string {
	if tls {
		return "https"
	}
	return "http"
}
