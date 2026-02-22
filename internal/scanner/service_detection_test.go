package scanner

import (
	"testing"
	"time"
)

func TestSSHVersionParsing(t *testing.T) {
	tests := []struct {
		banner  string
		version string
	}{
		{
			banner:  "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n",
			version: "OpenSSH_8.9p1",
		},
		{
			banner:  "SSH-2.0-dropbear_2022.83\r\n",
			version: "dropbear_2022.83",
		},
		{
			banner:  "SSH-2.0-\r\n",
			version: "",
		},
	}
	for _, tt := range tests {
		m := sshVersionRe.FindStringSubmatch(tt.banner)
		got := ""
		if len(m) > 1 {
			got = m[1]
		}
		if got != tt.version {
			t.Errorf("banner %q: got %q, want %q", tt.banner, got, tt.version)
		}
	}
}

func TestSMTPVersionParsing(t *testing.T) {
	tests := []struct {
		banner  string
		version string
	}{
		{
			banner:  "220 mail.example.com ESMTP Postfix\r\n",
			version: "Postfix",
		},
		{
			banner:  "220 smtp.example.com Sendmail\r\n",
			version: "Sendmail",
		},
	}
	for _, tt := range tests {
		m := smtpVersionRe.FindStringSubmatch(tt.banner)
		got := ""
		if len(m) > 1 {
			got = m[1]
		}
		if got != tt.version {
			t.Errorf("banner %q: got %q, want %q", tt.banner, got, tt.version)
		}
	}
}

func TestDetectServiceClosedPort(t *testing.T) {
	result := DetectService("127.0.0.1", 1, 100*time.Millisecond)
	if result.Name != "closed" {
		t.Errorf("expected closed, got %s", result.Name)
	}
}
