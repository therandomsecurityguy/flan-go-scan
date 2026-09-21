package scanner

import (
	"strings"
	"testing"
)

func TestCPEVersionIsWildcard(t *testing.T) {
	cases := map[string]bool{
		"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*":     true,
		"cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*": false,
		"cpe:2.3:a:openbsd:openssh:6.6.1p1":                false,
		"cpe:2.3:o:canonical:ubuntu_linux:*":               true,
	}
	for cpe, want := range cases {
		if got := cpeVersionIsWildcard(cpe); got != want {
			t.Fatalf("cpeVersionIsWildcard(%q) = %v, want %v", cpe, got, want)
		}
	}
}

func TestCVETitleJumpsToImpact(t *testing.T) {
	desc := "The mod_ssl module in the Apache HTTP Server 2.2.x before 2.2.21 allows remote attackers to cause a denial of service (process crash) via a crafted request."
	title := cveTitle([]cveDescription{{Lang: "en", Value: desc}})
	if want := "remote attackers to cause a denial of service (process crash) via a crafted request"; !strings.HasPrefix(title, want) {
		t.Fatalf("cveTitle = %q, want prefix %q", title, want)
	}
}

func TestCVETitleStripsProductVersionPrefix(t *testing.T) {
	desc := "In Apache httpd 2.2.x before 2.2.33 and 2.4.x before 2.4.26, use of the ap_get_basic_auth_pw() function outside of the authentication phase may lead to authentication bypass."
	title := cveTitle([]cveDescription{{Lang: "en", Value: desc}})
	if want := "use of the ap_get_basic_auth_pw()"; !strings.HasPrefix(title, want) {
		t.Fatalf("cveTitle = %q, want prefix %q", title, want)
	}
}

func TestCVETitleTruncatesLongDescriptions(t *testing.T) {
	long := strings.Repeat("word ", 60)
	title := cveTitle([]cveDescription{{Lang: "en", Value: long}})
	if len(title) > 100 {
		t.Fatalf("cveTitle too long: %d", len(title))
	}
	if !strings.HasSuffix(title, "...") {
		t.Fatalf("cveTitle should end with ellipsis, got %q", title)
	}
}

func TestCVETitlePrefersEnglish(t *testing.T) {
	title := cveTitle([]cveDescription{
		{Lang: "es", Value: "descripción en español"},
		{Lang: "en", Value: "english description"},
	})
	if title != "english description" {
		t.Fatalf("cveTitle = %q, want %q", title, "english description")
	}
}

func TestSortCVEsBySeverity(t *testing.T) {
	cves := []CVE{
		{ID: "CVE-2020-0001", Severity: "MEDIUM", Score: 5.3},
		{ID: "CVE-2019-0002", Severity: "CRITICAL", Score: 9.8},
		{ID: "CVE-2018-0003", Severity: "HIGH", Score: 7.5},
		{ID: "CVE-2017-0004", Severity: "CRITICAL", Score: 10.0},
	}
	SortCVEs(cves)
	want := []string{"CVE-2017-0004", "CVE-2019-0002", "CVE-2018-0003", "CVE-2020-0001"}
	for i, id := range want {
		if cves[i].ID != id {
			t.Fatalf("cves[%d] = %q, want %q", i, cves[i].ID, id)
		}
	}
}

func TestCVESeverityCounts(t *testing.T) {
	counts := CVESeverityCounts([]CVE{
		{ID: "A", Severity: "HIGH"},
		{ID: "B", Severity: "high"},
		{ID: "C", Severity: "LOW"},
	})
	if counts["HIGH"] != 2 || counts["LOW"] != 1 {
		t.Fatalf("unexpected counts: %v", counts)
	}
	if CVESeverityCounts([]CVE{{ID: "A"}}) != nil {
		t.Fatal("expected nil counts when no severities present")
	}
}
