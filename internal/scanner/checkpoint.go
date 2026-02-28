package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Checkpoint struct {
	filePath string
	mu       sync.Mutex
	Progress map[string]map[int]bool
	dirty    bool
}

type checkpointDisk struct {
	Progress map[string]map[int]bool `json:"progress"`
}

func NewCheckpoint(path string) (*Checkpoint, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("invalid checkpoint path: %w", err)
	}
	cp := &Checkpoint{
		filePath: abs,
		Progress: make(map[string]map[int]bool),
	}
	cp.cleanupStaleTempFiles(filepath.Dir(abs))
	if err := cp.Load(); err != nil {
		return nil, err
	}
	return cp, nil
}

func (c *Checkpoint) cleanupStaleTempFiles(dir string) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	prefix := filepath.Base(c.filePath) + ".tmp."
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), prefix) {
			os.Remove(filepath.Join(dir, entry.Name()))
		}
	}
}

func (c *Checkpoint) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if strings.TrimSpace(string(data)) == "" {
		return nil
	}

	var wrapped checkpointDisk
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Progress != nil {
		c.Progress = wrapped.Progress
		return nil
	}

	var legacy map[string]map[int]bool
	if err := json.Unmarshal(data, &legacy); err != nil {
		return err
	}
	c.Progress = legacy
	return nil
}

func (c *Checkpoint) Save(host string, port int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.Progress[host] == nil {
		c.Progress[host] = make(map[int]bool)
	}
	c.Progress[host][port] = true
	c.dirty = true
}

func (c *Checkpoint) Flush() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.dirty {
		return nil
	}
	data, err := json.MarshalIndent(checkpointDisk{Progress: c.Progress}, "", "  ")
	if err != nil {
		return err
	}

	tmp := c.filePath + ".tmp." + fmt.Sprintf("%d", time.Now().UnixNano())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}

	if err := os.Rename(tmp, c.filePath); err != nil {
		os.Remove(tmp)
		return err
	}

	c.dirty = false
	return nil
}

func (c *Checkpoint) ShouldSkip(host string, port int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	ports, exists := c.Progress[host]
	if !exists {
		return false
	}
	return ports[port]
}

func (c *Checkpoint) Clear() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Progress = make(map[string]map[int]bool)
	c.dirty = false
	dir := filepath.Dir(c.filePath)
	tmp := filepath.Join(dir, ".checkpoint.tmp")
	os.Remove(tmp)
	if err := os.Remove(c.filePath); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
