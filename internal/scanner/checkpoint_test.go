package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckpointLoadLegacyFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	legacy := map[string]map[int]bool{
		"10.0.0.1": {80: true, 443: true},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal legacy checkpoint: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write legacy checkpoint: %v", err)
	}

	cp, err := NewCheckpoint(path)
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if !cp.ShouldSkip("10.0.0.1", 80) || !cp.ShouldSkip("10.0.0.1", 443) {
		t.Fatalf("expected legacy ports to be restored: %+v", cp.Progress["10.0.0.1"])
	}
}

func TestCheckpointLoadWrappedFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	payload := checkpointDisk{
		Progress: map[string]map[int]bool{
			"192.168.1.10": {22: true},
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal wrapped checkpoint: %v", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("write wrapped checkpoint: %v", err)
	}

	cp, err := NewCheckpoint(path)
	if err != nil {
		t.Fatalf("load checkpoint: %v", err)
	}
	if !cp.ShouldSkip("192.168.1.10", 22) {
		t.Fatalf("expected wrapped checkpoint entry to be restored")
	}
}

func TestCheckpointLoadRejectsCorruptData(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	if err := os.WriteFile(path, []byte("{"), 0600); err != nil {
		t.Fatalf("write corrupt checkpoint: %v", err)
	}
	if _, err := NewCheckpoint(path); err == nil {
		t.Fatal("expected corrupt checkpoint to return an error")
	}
}

func TestCheckpointFlushWritesWrappedFormat(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")

	cp, err := NewCheckpoint(path)
	if err != nil {
		t.Fatalf("create checkpoint: %v", err)
	}
	cp.Save("172.16.1.3", 3306)
	if err := cp.Flush(); err != nil {
		t.Fatalf("flush checkpoint: %v", err)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read checkpoint: %v", err)
	}

	var payload checkpointDisk
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal checkpoint: %v", err)
	}
	if !payload.Progress["172.16.1.3"][3306] {
		t.Fatalf("expected flushed checkpoint entry to exist")
	}
}
