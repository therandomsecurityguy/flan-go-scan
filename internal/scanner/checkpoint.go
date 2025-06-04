package scanner

import (
	"encoding/json"
	"os"
	"sync"
)

type Checkpoint struct {
	filePath string
	mu       sync.Mutex
	Progress map[string]int // host -> last scanned port
}

func NewCheckpoint(path string) *Checkpoint {
	cp := &Checkpoint{
		filePath: path,
		Progress: make(map[string]int),
	}
	cp.Load()
	return cp
}

func (c *Checkpoint) Load() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	data, err := os.ReadFile(c.filePath)
	if err != nil {
		return nil // not fatal
	}
	return json.Unmarshal(data, &c.Progress)
}

func (c *Checkpoint) Save(host string, port int) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.Progress[host] = port
	data, err := json.MarshalIndent(c.Progress, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(c.filePath, data, 0644)
}

func (c *Checkpoint) ShouldSkip(host string, port int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	lastPort, exists := c.Progress[host]
	return exists && port <= lastPort
}
