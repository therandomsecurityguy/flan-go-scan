package dns

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadWordlist(t *testing.T) {
	path := filepath.Join(t.TempDir(), "words.txt")
	content := "www\n\n api \nadmin\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write wordlist: %v", err)
	}

	words, err := LoadWordlist(path)
	if err != nil {
		t.Fatalf("LoadWordlist failed: %v", err)
	}
	if len(words) != 3 {
		t.Fatalf("expected 3 words, got %d (%v)", len(words), words)
	}
	if words[0] != "www" || words[1] != "api" || words[2] != "admin" {
		t.Fatalf("unexpected words: %v", words)
	}
}

func TestEnumerateWithInvalidDomainFailsFast(t *testing.T) {
	e := NewEnumerator(200*time.Millisecond, 4)
	_, err := e.EnumerateWithWordlist(context.Background(), "not-a-domain", []string{"www"})
	if err == nil {
		t.Fatal("expected invalid domain to return an error")
	}
}
