package output

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func TestWriteCSV(t *testing.T) {
	dir := t.TempDir()
	w, err := NewReportWriter(dir)
	if err != nil {
		t.Fatalf("NewReportWriter failed: %v", err)
	}

	results := []scanner.ScanResult{
		{
			Host:     "127.0.0.1",
			Port:     80,
			Protocol: "tcp",
			Service:  "http",
			Version:  "nginx",
		},
	}
	if err := w.WriteCSV(results); err != nil {
		t.Fatalf("WriteCSV failed: %v", err)
	}

	matches, err := filepath.Glob(filepath.Join(dir, "scan-*.csv"))
	if err != nil {
		t.Fatalf("glob failed: %v", err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one CSV report, got %d", len(matches))
	}
	data, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatalf("read report: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "Host,Port,Protocol,Service") || !strings.Contains(text, "127.0.0.1,80,tcp,http,nginx") {
		t.Fatalf("unexpected CSV content: %s", text)
	}
}

func TestJSONLWriter(t *testing.T) {
	dir := t.TempDir()
	jw, err := NewJSONLWriter(dir)
	if err != nil {
		t.Fatalf("NewJSONLWriter failed: %v", err)
	}
	t.Cleanup(func() {
		_ = jw.Close()
	})

	if err := jw.WriteResult(scanner.ScanResult{
		Host:    "10.0.0.1",
		Port:    443,
		Service: "https",
	}); err != nil {
		t.Fatalf("WriteResult failed: %v", err)
	}
	if err := jw.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}
	data, err := os.ReadFile(jw.Filename)
	if err != nil {
		t.Fatalf("read JSONL report: %v", err)
	}
	if !strings.Contains(string(data), `"host":"10.0.0.1"`) {
		t.Fatalf("unexpected JSONL content: %s", string(data))
	}
}
