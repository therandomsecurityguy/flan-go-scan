package scanner

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var cpeVersionStarRe = regexp.MustCompile(`^cpe:2\.3:[aho]:([^:]+):([^:]+):\*(:.*)?$`)

var cpeVersionValidRe = regexp.MustCompile(`^[0-9][0-9A-Za-z.+-]*$`)

type bannerCPEPattern struct {
	re  *regexp.Regexp
	cpe string
}

var bannerCPEPatterns = []bannerCPEPattern{
	{regexp.MustCompile(`OpenSSH_([0-9][0-9A-Za-z.+-]*)`), "cpe:2.3:a:openbsd:openssh:%s"},
	{regexp.MustCompile(`(?i)Apache/([0-9][0-9A-Za-z.+-]*)`), "cpe:2.3:a:apache:http_server:%s"},
	{regexp.MustCompile(`(?i)nginx/([0-9][0-9A-Za-z.+-]*)`), "cpe:2.3:a:f5:nginx:%s"},
	{regexp.MustCompile(`(?i)PostgreSQL ([0-9][0-9A-Za-z.+-]*)`), "cpe:2.3:a:postgresql:postgresql:%s"},
}

// serviceCPEs maps fingerprintx protocol names to CPE templates for
// services that report a product version at the top level.
var serviceCPEs = map[string]string{
	"mysql": "cpe:2.3:a:oracle:mysql:%s",
	"mssql": "cpe:2.3:a:microsoft:sql_server:%s",
}

var distroVersionSuffixRe = regexp.MustCompile(`^([0-9]+(\.[0-9]+)*[a-z]?)-.*$`)

// normalizeServiceVersion trims distro-style suffixes such as
// "8.0.28-0ubuntu0.21.04.1" down to "8.0.28" so NVD version matching works.
func normalizeServiceVersion(v string) string {
	if m := distroVersionSuffixRe.FindStringSubmatch(v); m != nil {
		return m[1]
	}
	return v
}

// EnrichCPEVersions fills versionless CPEs in metadata using versions detected
// in the technologies list and derives additional CPEs from service identity,
// banners, and version strings.
func EnrichCPEVersions(metadata []byte, service, version, banner string) []byte {
	raw := map[string]any{}
	if len(metadata) > 0 {
		if err := json.Unmarshal(metadata, &raw); err != nil {
			return metadata
		}
	}

	texts := []string{version, banner}
	if b, ok := raw["banner"].(string); ok && b != "" {
		texts = append(texts, b)
	}
	if headers, ok := raw["responseHeaders"].(map[string]any); ok {
		if servers, ok := headers["Server"].([]any); ok {
			for _, s := range servers {
				if sv, ok := s.(string); ok && sv != "" {
					texts = append(texts, sv)
				}
			}
		}
	}

	var technologies []string
	if techs, ok := raw["technologies"].([]any); ok {
		for _, t := range techs {
			if ts, ok := t.(string); ok {
				technologies = append(technologies, ts)
			}
		}
	}

	cpes := metadataCPEs(raw)
	changed := false

	for i, cpe := range cpes {
		if v := cpeVersionFromTechnologies(cpe, technologies); v != "" {
			cpes[i] = substituteCPEVersion(cpe, v)
			changed = true
		}
	}

	if tpl, ok := serviceCPEs[strings.ToLower(service)]; ok && version != "" {
		if v := normalizeServiceVersion(version); cpeVersionValidRe.MatchString(v) {
			var upserted bool
			cpes, upserted = upsertVersionedCPE(cpes, fmt.Sprintf(tpl, v))
			changed = changed || upserted
		}
	}

	for _, text := range texts {
		if text == "" {
			continue
		}
		for _, m := range bannerCPEPatterns {
			match := m.re.FindStringSubmatch(text)
			if len(match) < 2 {
				continue
			}
			cpe := fmt.Sprintf(m.cpe, match[1])
			var upserted bool
			cpes, upserted = upsertVersionedCPE(cpes, cpe)
			changed = changed || upserted
		}
	}

	if !changed {
		return metadata
	}

	raw["cpes"] = cpes
	out, err := json.Marshal(raw)
	if err != nil {
		return metadata
	}
	return out
}

func metadataCPEs(raw map[string]any) []string {
	switch existing := raw["cpes"].(type) {
	case []any:
		cpes := make([]string, 0, len(existing))
		for _, c := range existing {
			if cs, ok := c.(string); ok && cs != "" {
				cpes = append(cpes, cs)
			}
		}
		return cpes
	case []string:
		return existing
	}
	return nil
}

func cpeVersionFromTechnologies(cpe string, technologies []string) string {
	m := cpeVersionStarRe.FindStringSubmatch(cpe)
	if m == nil {
		return ""
	}
	vendor := strings.ToLower(m[1])
	productName := strings.ReplaceAll(strings.ToLower(m[2]), "_", " ")
	for _, tech := range technologies {
		name, ver, ok := strings.Cut(tech, ":")
		if !ok || !cpeVersionValidRe.MatchString(ver) {
			continue
		}
		lower := strings.ToLower(name)
		if strings.Contains(lower, vendor) ||
			strings.Contains(lower, productName) ||
			(len(lower) >= 4 && strings.Contains(productName, lower)) {
			return ver
		}
	}
	return ""
}

func substituteCPEVersion(cpe, version string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return cpe
	}
	parts[5] = version
	return strings.Join(parts, ":")
}

func cpeBase(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return cpe
	}
	return strings.Join(parts[2:5], ":")
}

func cpeVersionSlot(cpe string) string {
	parts := strings.Split(cpe, ":")
	if len(parts) < 6 {
		return ""
	}
	return parts[5]
}

func upsertVersionedCPE(cpes []string, cpe string) ([]string, bool) {
	base := cpeBase(cpe)
	for i, existing := range cpes {
		if cpeBase(existing) != base {
			continue
		}
		if existing == cpe {
			return cpes, false
		}
		if cpeVersionSlot(existing) == "*" || cpeVersionSlot(existing) == "" {
			cpes[i] = cpe
			return cpes, true
		}
		return cpes, false
	}
	return append(cpes, cpe), true
}
