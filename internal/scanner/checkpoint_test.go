package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

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
