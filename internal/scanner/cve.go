package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

type CVE struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity,omitempty"`
	Score    float64 `json:"score,omitempty"`
}

type CVELookup struct {
	client  *http.Client
	cache   map[string][]CVE
	mu      sync.Mutex
	last    time.Time
}

func NewCVELookup() *CVELookup {
	return &CVELookup{
		client: &http.Client{Timeout: 15 * time.Second},
		cache:  make(map[string][]CVE),
	}
}

func (c *CVELookup) Lookup(cpe string) []CVE {
	if strings.Contains(cpe, ":*:*:*:*:*:*:*") {
		return nil
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if cached, ok := c.cache[cpe]; ok {
		return cached
	}

	elapsed := time.Since(c.last)
	if elapsed < 6*time.Second {
		time.Sleep(6*time.Second - elapsed)
	}
	c.last = time.Now()

	cves := c.queryNVD(cpe)
	c.cache[cpe] = cves
	return cves
}

func (c *CVELookup) queryNVD(cpe string) []CVE {
	u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=20", url.QueryEscape(cpe))

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		slog.Warn("NVD request build failed", "cpe", cpe, "err", err)
		return nil
	}
	req.Header.Set("User-Agent", "flan/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		slog.Warn("NVD query failed", "cpe", cpe, "err", err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Warn("NVD returned non-200", "cpe", cpe, "status", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	var result struct {
		Vulnerabilities []struct {
			CVE struct {
				ID      string `json:"id"`
				Metrics struct {
					CvssV31 []struct {
						CvssData struct {
							BaseScore    float64 `json:"baseScore"`
							BaseSeverity string  `json:"baseSeverity"`
						} `json:"cvssData"`
					} `json:"cvssMetricV31"`
				} `json:"metrics"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		slog.Warn("NVD parse failed", "cpe", cpe, "err", err)
		return nil
	}

	var cves []CVE
	for _, v := range result.Vulnerabilities {
		cve := CVE{ID: v.CVE.ID}
		if len(v.CVE.Metrics.CvssV31) > 0 {
			cve.Score = v.CVE.Metrics.CvssV31[0].CvssData.BaseScore
			cve.Severity = v.CVE.Metrics.CvssV31[0].CvssData.BaseSeverity
		}
		cves = append(cves, cve)
	}
	return cves
}
