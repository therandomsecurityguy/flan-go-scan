package output

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReadScanResultsJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.json")
	if err := os.WriteFile(path, []byte(`[
  {"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http"},
  {"host":"2.2.2.2","port":443,"protocol":"tcp","service":"https"}
]`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	results, err := ReadScanResults(path)
	if err != nil {
		t.Fatalf("ReadScanResults returned error: %v", err)
	}
	if got, want := len(results), 2; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if got, want := results[1].Host, "2.2.2.2"; got != want {
		t.Fatalf("results[1].Host = %q, want %q", got, want)
	}
}

func TestReadScanResultsJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "scan.jsonl")
	if err := os.WriteFile(path, []byte(`{"host":"1.1.1.1","port":80,"protocol":"tcp","service":"http"}
{"host":"2.2.2.2","port":443,"protocol":"tcp","service":"https"}
`), 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	results, err := ReadScanResults(path)
	if err != nil {
		t.Fatalf("ReadScanResults returned error: %v", err)
	}
	if got, want := len(results), 2; got != want {
		t.Fatalf("len(results) = %d, want %d", got, want)
	}
	if got, want := results[0].Service, "http"; got != want {
		t.Fatalf("results[0].Service = %q, want %q", got, want)
	}
}

func TestReadScanResultsEmptyInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if _, err := ReadScanResults(path); err == nil {
		t.Fatal("expected error for empty input")
	}
}
