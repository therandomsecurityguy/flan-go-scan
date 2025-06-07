package scanner

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

type Vulnerability struct {
	ID          string
	Description string
	Severity    string
	Reference   string
}

type VulnersAPI struct {
	APIKey string
	Client *http.Client
}

func NewVulnersAPI(apiKey string) *VulnersAPI {
	return &VulnersAPI{
		APIKey: apiKey,
		Client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (v *VulnersAPI) Query(software string, version string) ([]Vulnerability, error) {
	url := fmt.Sprintf("https://vulners.com/api/v3/search/lucene/?query=type:%%22%s%%20%s%%22", software, version)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("X-Vulners-API-Key", v.APIKey)

	resp, err := v.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Use io.ReadAll instead of ioutil.ReadAll
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var result struct {
		Data struct {
			Documents []struct {
				ID          string `json:"id"`
				Description string `json:"description"`
				CVSS        struct {
					Score float64 `json:"score"`
				} `json:"cvss"`
			} `json:"documents"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &result); err != nil {
		return nil, err
	}

	var vulns []Vulnerability
	for _, doc := range result.Data.Documents {
		vulns = append(vulns, Vulnerability{
			ID:          doc.ID,
			Description: doc.Description,
			Severity:    cvssScoreToSeverity(doc.CVSS.Score),
			Reference:   fmt.Sprintf("https://vulners.com/%s", doc.ID),
		})
	}
	return vulns, nil
}

func cvssScoreToSeverity(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	default:
		return "Low"
	}
}

// Example function to read a local JSON file (using os.ReadFile instead of ioutil.ReadFile)
func ReadLocalVulnDB(path string) ([]Vulnerability, error) {
	// Use os.ReadFile instead of ioutil.ReadFile
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var vulns []Vulnerability
	if err := json.Unmarshal(data, &vulns); err != nil {
		return nil, err
	}
	return vulns, nil
}
