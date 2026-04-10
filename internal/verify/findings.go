package verify

import (
	"fmt"
	"strings"
)

func BuildFindings(executions []ExecutionResult) []Finding {
	if len(executions) == 0 {
		return nil
	}

	seen := make(map[string]struct{}, len(executions))
	findings := make([]Finding, 0, len(executions))
	for _, execution := range executions {
		finding, ok := findingFromExecution(execution)
		if !ok {
			continue
		}
		key := finding.ID
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		findings = append(findings, finding)
	}
	return findings
}

func findingFromExecution(execution ExecutionResult) (Finding, bool) {
	if len(execution.Evidence.Matches) == 0 {
		return Finding{}, false
	}

	match := execution.Evidence.Matches[0]
	severity, confidence, remediation, references := findingMetadata(execution.Candidate.Family)
	evidence := execution.Evidence
	evidence.Matcher = match.Name
	if strings.TrimSpace(match.Detail) != "" {
		evidence.Detail = match.Detail
	}

	finding := Finding{
		ID:          findingID(execution.Candidate, match.Name),
		CheckID:     execution.Candidate.CheckID,
		Family:      execution.Candidate.Family,
		Adapter:     execution.Candidate.Adapter,
		Severity:    severity,
		Confidence:  confidence,
		Asset:       execution.Candidate.Asset,
		Surface:     execution.Candidate.Surface,
		Reasons:     dedupeStrings(execution.Candidate.Reasons),
		References:  references,
		Remediation: remediation,
		Evidence:    evidence,
	}
	return finding, true
}

func findingID(candidate CandidateCheck, matcher string) string {
	path := ""
	if candidate.Surface != nil {
		path = normalizeSurfacePath(candidate.Surface.Path)
	}
	return fmt.Sprintf(
		"%s|%s|%s|%d|%s|%s",
		candidate.Family,
		candidate.Adapter,
		candidate.Asset.Host,
		candidate.Asset.Port,
		path,
		strings.TrimSpace(matcher),
	)
}

func findingMetadata(family string) (severity string, confidence string, remediation string, references []string) {
	switch family {
	case "open-redirect":
		return "medium", "high", "Allow only relative redirect targets or enforce an explicit allowlist for external destinations.", []string{"CWE-601"}
	case "traversal-read":
		return "high", "high", "Restrict file and path inputs to an allowlist and reject traversal sequences before accessing the filesystem.", []string{"CWE-22"}
	case "unauth-api":
		return "high", "high", "Require authentication or explicitly constrain unauthenticated access for this API surface.", []string{"CWE-306"}
	default:
		return "medium", "high", "Review this surface and apply the family-specific fix before rerunning verification.", nil
	}
}
