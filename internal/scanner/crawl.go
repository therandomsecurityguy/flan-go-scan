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
	Server    string   `json:"server,omitempty"`
	PoweredBy string   `json:"powered_by,omitempty"`
	Generator string   `json:"generator,omitempty"`
	Apps      []string `json:"apps,omitempty"`
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

func Crawl(ctx context.Context, scheme, ip, hostname string, port int, maxDepth int, timeout time.Duration, reqDelay time.Duration) ([]CrawlResult, *AppFingerprint) {
	displayHost := ip
	if strings.Contains(ip, ":") {
		displayHost = "[" + ip + "]"
	}
	base := fmt.Sprintf("%s://%s:%d", scheme, displayHost, port)

	crawlTimeout := timeout * 3
	if crawlTimeout > 8*time.Second {
		crawlTimeout = 8 * time.Second
	}
	tlsCfg := &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	if hostname != "" && net.ParseIP(hostname) == nil {
		tlsCfg.ServerName = hostname
	}
	client := &http.Client{
		Timeout: crawlTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsCfg,
		},
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
	fp := &AppFingerprint{}
	var results []CrawlResult

	queue := make([]entry, 0, len(sensitivePaths)+1)
	for _, p := range sensitivePaths {
		queue = append(queue, entry{p, 0})
	}
	queue = append(queue, entry{"/", 0})
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
				if fp.Server == "" && fp.PoweredBy == "" && fp.Generator == "" && len(fp.Apps) == 0 {
					return results, nil
				}
				return results, fp
			case <-timer.C:
			}
		}

		cr, body := fetchPath(ctx, client, base, hostname, e.path, fp, appsFound)
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
					slog.Info("robots.txt disallow entry (target for crawl)", "path", disallowed)
					queue = append(queue, entry{disallowed, e.depth})
				}
			}
		}

		if e.depth < maxDepth && strings.Contains(cr.ContentType, "text/html") && body != "" && cr.StatusCode < 400 {
			for _, link := range extractLinks(body, base) {
				if !visited[link] {
					queue = append(queue, entry{link, e.depth + 1})
				}
			}
		}
	}

	if fp.Server == "" && fp.PoweredBy == "" && fp.Generator == "" && len(fp.Apps) == 0 {
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

func fetchPath(ctx context.Context, client *http.Client, base, hostname, path string, fp *AppFingerprint, appsFound map[string]bool) (*CrawlResult, string) {
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

	return cr, body
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
