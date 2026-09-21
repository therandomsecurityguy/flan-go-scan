package scanner

import (
	"encoding/json"
	"testing"
)

func metadataCPEList(t *testing.T, metadata []byte) []string {
	t.Helper()
	var raw struct {
		CPEs []string `json:"cpes"`
	}
	if err := json.Unmarshal(metadata, &raw); err != nil {
		t.Fatalf("unmarshal metadata: %v", err)
	}
	return raw.CPEs
}

func TestEnrichCPEVersionsSSHBanner(t *testing.T) {
	metadata := []byte(`{"banner":"SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13\r\n","passwordAuthEnabled":true,"algo":""}`)
	out := EnrichCPEVersions(metadata, "ssh", "", "")
	cpes := metadataCPEList(t, out)
	want := "cpe:2.3:a:openbsd:openssh:6.6.1p1"
	found := false
	for _, cpe := range cpes {
		if cpe == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected %s in cpes, got %v", want, cpes)
	}
}

func TestEnrichCPEVersionsTechnologySubstitution(t *testing.T) {
	metadata := []byte(`{"statusCode":200,"technologies":["Ubuntu","Apache HTTP Server:2.4.7"],"cpes":["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*","cpe:2.3:o:canonical:ubuntu_linux:*:*:*:*:*:*:*:*"]}`)
	out := EnrichCPEVersions(metadata, "http", "Apache/2.4.7 (Ubuntu)", "")
	cpes := metadataCPEList(t, out)
	hasVersioned := false
	for _, cpe := range cpes {
		if cpe == "cpe:2.3:a:apache:http_server:2.4.7:*:*:*:*:*:*:*" {
			hasVersioned = true
		}
	}
	if !hasVersioned {
		t.Fatalf("expected versioned apache CPE, got %v", cpes)
	}
}

func TestEnrichCPEVersionsMySQLServiceVersion(t *testing.T) {
	metadata := []byte(`{"protocolVersion":10,"serverVersion":"8.0.28"}`)
	out := EnrichCPEVersions(metadata, "MySQL", "8.0.28-0ubuntu0.21.04.1", "")
	cpes := metadataCPEList(t, out)
	want := "cpe:2.3:a:oracle:mysql:8.0.28"
	if len(cpes) != 1 || cpes[0] != want {
		t.Fatalf("expected %s, got %v", want, cpes)
	}
}

func TestEnrichCPEVersionsPreservesUnknownMetadata(t *testing.T) {
	metadata := []byte(`{"unexpected":true}`)
	out := EnrichCPEVersions(metadata, "unknown", "", "")
	if string(out) != string(metadata) {
		t.Fatalf("expected metadata unchanged, got %s", out)
	}
}

func TestNormalizeServiceVersion(t *testing.T) {
	cases := map[string]string{
		"8.0.28-0ubuntu0.21.04.1": "8.0.28",
		"13.3":                    "13.3",
		"1.3.3a":                  "1.3.3a",
	}
	for in, want := range cases {
		if got := normalizeServiceVersion(in); got != want {
			t.Fatalf("normalizeServiceVersion(%q) = %q, want %q", in, got, want)
		}
	}
}
