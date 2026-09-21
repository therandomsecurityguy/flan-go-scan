package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
	"golang.org/x/time/rate"
)

type CVE struct {
	ID          string  `json:"id"`
	Severity    string  `json:"severity,omitempty"`
	Score       float64 `json:"score,omitempty"`
	Description string  `json:"description,omitempty"`
}

// CVEMatch carries the full NVD result set for one CPE: the sorted CVE list,
// the total number of matching CVEs, and their severity distribution.
type CVEMatch struct {
	CVEs   []CVE          `json:"cves"`
	Total  int            `json:"total"`
	Counts map[string]int `json:"counts,omitempty"`
}

type CVELookup struct {
	client  *http.Client
	cache   map[string]CVEMatch
	mu      sync.RWMutex
	sf      singleflight.Group
	limiter *rate.Limiter
}

type cvssMetric struct {
	CvssData struct {
		BaseScore    float64 `json:"baseScore"`
		BaseSeverity string  `json:"baseSeverity"`
	} `json:"cvssData"`
}

type cveMetrics struct {
	CvssV31 []cvssMetric `json:"cvssMetricV31"`
	CvssV30 []cvssMetric `json:"cvssMetricV30"`
	CvssV2  []cvssMetric `json:"cvssMetricV2"`
}

type cveDescription struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

func NewCVELookup() *CVELookup {
	return &CVELookup{
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        10,
				MaxIdleConnsPerHost: 5,
				IdleConnTimeout:     30 * time.Second,
			},
		},
		cache:   make(map[string]CVEMatch),
		limiter: rate.NewLimiter(rate.Every(6*time.Second), 5),
	}
}

func (c *CVELookup) Lookup(ctx context.Context, cpe string) CVEMatch {
	if cpeVersionIsWildcard(cpe) {
		return CVEMatch{}
	}

	c.mu.RLock()
	if cached, ok := c.cache[cpe]; ok {
		c.mu.RUnlock()
		return cached
	}
	c.mu.RUnlock()

	v, err, _ := c.sf.Do(cpe, func() (interface{}, error) {
		if err := c.limiter.Wait(ctx); err != nil {
			return nil, err
		}
		match, err := c.queryNVD(ctx, cpe)
		if err != nil {
			return nil, err
		}

		c.mu.Lock()
		c.cache[cpe] = match
		c.mu.Unlock()

		return match, nil
	})
	if err != nil {
		return CVEMatch{}
	}

	if match, ok := v.(CVEMatch); ok {
		return match
	}
	return CVEMatch{}
}

func (c *CVELookup) queryNVD(ctx context.Context, cpe string) (CVEMatch, error) {
	u := fmt.Sprintf("https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=%s&resultsPerPage=2000", url.QueryEscape(cpe))

	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		slog.Warn("NVD request build failed", "cpe", cpe, "err", err)
		return CVEMatch{}, err
	}
	req.Header.Set("User-Agent", "flan/1.0")

	resp, err := c.client.Do(req)
	if err != nil {
		slog.Warn("NVD query failed", "cpe", cpe, "err", err)
		return CVEMatch{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		slog.Warn("NVD returned non-200", "cpe", cpe, "status", resp.StatusCode)
		return CVEMatch{}, fmt.Errorf("unexpected NVD status: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return CVEMatch{}, err
	}

	var result struct {
		TotalResults int `json:"totalResults"`
		Vulnerabilities []struct {
			CVE struct {
				ID           string          `json:"id"`
				Metrics      cveMetrics      `json:"metrics"`
				Descriptions []cveDescription `json:"descriptions"`
			} `json:"cve"`
		} `json:"vulnerabilities"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		slog.Warn("NVD parse failed", "cpe", cpe, "err", err)
		return CVEMatch{}, err
	}

	var cves []CVE
	for _, v := range result.Vulnerabilities {
		cve := CVE{
			ID:          v.CVE.ID,
			Description: cveTitle(v.CVE.Descriptions),
		}
		score, severity := extractCVESeverity(v.CVE.Metrics)
		if severity != "" {
			cve.Score = score
			cve.Severity = severity
		}
		cves = append(cves, cve)
	}
	SortCVEs(cves)
	return CVEMatch{
		CVEs:   cves,
		Total:  result.TotalResults,
		Counts: CVESeverityCounts(cves),
	}, nil
}

func extractCVESeverity(metrics cveMetrics) (float64, string) {
	if len(metrics.CvssV31) > 0 {
		return metrics.CvssV31[0].CvssData.BaseScore, metrics.CvssV31[0].CvssData.BaseSeverity
	}
	if len(metrics.CvssV30) > 0 {
		return metrics.CvssV30[0].CvssData.BaseScore, metrics.CvssV30[0].CvssData.BaseSeverity
	}
	if len(metrics.CvssV2) > 0 {
		return metrics.CvssV2[0].CvssData.BaseScore, metrics.CvssV2[0].CvssData.BaseSeverity
	}
	return 0, ""
}

// cveVersionIsWildcard reports whether a CPE 2.3 name lacks a concrete
// version in its version slot (e.g. `cpe:2.3:a:apache:http_server:*`).
// Versionless CPEs are skipped because NVD would return every CVE ever
// recorded for the product.
func cpeVersionIsWildcard(cpe string) bool {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return false
	}
	return parts[5] == "*"
}

// SortCVEs orders CVEs most severe first.
func SortCVEs(cves []CVE) {
	sort.SliceStable(cves, func(i, j int) bool {
		left, right := cves[i], cves[j]
		if left.Score != right.Score {
			return left.Score > right.Score
		}
		if rank := severityRank(left.Severity) - severityRank(right.Severity); rank != 0 {
			return rank < 0
		}
		return left.ID < right.ID
	})
}

func severityRank(severity string) int {
	switch strings.ToUpper(strings.TrimSpace(severity)) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	}
	return 4
}

// CVESeverityCounts summarizes how many CVEs fall in each CVSS severity band.
func CVESeverityCounts(cves []CVE) map[string]int {
	counts := make(map[string]int)
	for _, cve := range cves {
		if cve.Severity == "" {
			continue
		}
		counts[strings.ToUpper(cve.Severity)]++
	}
	if len(counts) == 0 {
		return nil
	}
	return counts
}

func cveEnglishDescription(list []cveDescription) string {
	for _, d := range list {
		if strings.EqualFold(d.Lang, "en") {
			return d.Value
		}
	}
	if len(list) > 0 {
		return list[0].Value
	}
	return ""
}

// cveTitle condenses a long NVD description into a short human-readable title.
func cveTitle(list []cveDescription) string {
	s := strings.Join(strings.Fields(cveEnglishDescription(list)), " ")
	if s == "" {
		return ""
	}
	s = strings.TrimPrefix(s, "The ")
	// Descriptions usually open with the affected component and version
	// range before describing the impact; jump to the impact when present.
	if idx := strings.Index(s, " allows "); idx >= 0 && idx < 160 {
		s = s[idx+len(" allows "):]
	} else if strings.HasPrefix(s, "In ") {
		// "In <product> <version range>, <impact>" — keep just the impact.
		if idx := strings.Index(s, ", "); idx >= 0 && idx < 160 {
			s = s[idx+len(", "):]
		}
	}
	s = strings.TrimSuffix(s, ".")
	if len(s) > 95 {
		if cut := strings.LastIndex(s[:95], " "); cut > 40 {
			s = s[:cut]
		}
		s += "..."
	}
	return s
}