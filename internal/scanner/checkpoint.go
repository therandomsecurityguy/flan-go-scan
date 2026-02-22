package scanner

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Checkpoint struct {
	filePath string
	mu       sync.Mutex
	Progress map[string]map[int]bool `json:"progress"`
	dirty    bool
}

func NewCheckpoint(path string) *Checkpoint {
	cp := &Checkpoint{
		filePath: path,
		Progress: make(map[string]map[int]bool),
	}
	cp.Load()
	return cp
}

func (c *Checkpoint) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return nil
	}
	return json.Unmarshal(data, &c.Progress)
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
	data, err := json.MarshalIndent(c.Progress, "", "  ")
	if err != nil {
		return err
	}
	tmp := c.filePath + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	c.dirty = false
	return os.Rename(tmp, c.filePath)
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
	return os.Remove(c.filePath)
}
