package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type HeaderFinding struct {
	Header   string `json:"header"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

func InspectHeaders(ctx context.Context, scheme, ip, hostname string, port int, timeout time.Duration) []HeaderFinding {
	displayHost := ip
	if strings.Contains(ip, ":") {
		displayHost = "[" + ip + "]"
	}
	target := fmt.Sprintf("%s://%s:%d/", scheme, displayHost, port)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil
	}
	host := ip
	if hostname != "" {
		host = hostname
	}
	req.Host = host
	req.Header.Set("User-Agent", "flan-scanner/1.0")

	client := &http.Client{
		Timeout: timeout * 2,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	defer io.Copy(io.Discard, resp.Body) //nolint:errcheck

	var findings []HeaderFinding

	check := func(header, severity, detail string) {
		findings = append(findings, HeaderFinding{Header: header, Severity: severity, Detail: detail})
	}

	h := resp.Header

	if scheme == "https" && h.Get("Strict-Transport-Security") == "" {
		check("Strict-Transport-Security", "HIGH", "missing HSTS header; browsers may connect over HTTP")
	}
	if h.Get("Content-Security-Policy") == "" {
		check("Content-Security-Policy", "MEDIUM", "missing CSP; XSS and injection attacks not mitigated")
	}
	if h.Get("X-Frame-Options") == "" && h.Get("Content-Security-Policy") == "" {
		check("X-Frame-Options", "MEDIUM", "missing; page may be embedded in iframes (clickjacking risk)")
	}
	if h.Get("X-Content-Type-Options") == "" {
		check("X-Content-Type-Options", "LOW", "missing; MIME sniffing enabled")
	}
	if h.Get("Referrer-Policy") == "" {
		check("Referrer-Policy", "LOW", "missing; full URL may be sent as Referer to third parties")
	}
	if h.Get("Permissions-Policy") == "" {
		check("Permissions-Policy", "LOW", "missing; browser features (camera, mic, geolocation) unrestricted")
	}

	if sv := h.Get("Server"); sv != "" && containsVersion(sv) {
		check("Server", "LOW", fmt.Sprintf("version disclosed: %s", sv))
	}
	if xp := h.Get("X-Powered-By"); xp != "" {
		check("X-Powered-By", "LOW", fmt.Sprintf("technology disclosed: %s", xp))
	}

	for _, cookie := range resp.Cookies() {
		var issues []string
		if scheme == "https" && !cookie.Secure {
			issues = append(issues, "missing Secure flag")
		}
		if !cookie.HttpOnly {
			issues = append(issues, "missing HttpOnly flag")
		}
		if cookie.SameSite == http.SameSiteDefaultMode {
			issues = append(issues, "missing SameSite attribute")
		}
		if len(issues) > 0 {
			check("Set-Cookie", "MEDIUM", fmt.Sprintf("cookie %q: %s", cookie.Name, strings.Join(issues, ", ")))
		}
	}

	for _, header := range []string{"Via", "X-Forwarded-For", "X-Real-IP", "X-Forwarded-Host"} {
		if v := h.Get(header); v != "" && isInternalIP(v) {
			check(header, "MEDIUM", fmt.Sprintf("internal IP leaked in %s: %s", header, v))
		}
	}

	return findings
}

func containsVersion(s string) bool {
	for _, c := range s {
		if c >= '0' && c <= '9' {
			return true
		}
	}
	return false
}

func isInternalIP(s string) bool {
	return strings.Contains(s, "10.") ||
		strings.Contains(s, "172.16.") ||
		strings.Contains(s, "172.17.") ||
		strings.Contains(s, "172.18.") ||
		strings.Contains(s, "172.19.") ||
		strings.Contains(s, "172.2") ||
		strings.Contains(s, "172.3") ||
		strings.Contains(s, "192.168.") ||
		strings.Contains(s, "127.")
}
