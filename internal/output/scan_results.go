package output

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

func ReadScanResults(path string) ([]scanner.ScanResult, error) {
	reader, closeFn, err := openScanResults(path)
	if err != nil {
		return nil, err
	}
	defer closeFn()

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("read scan results: %w", err)
	}

	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("read scan results: empty input")
	}

	if trimmed[0] == '[' {
		var results []scanner.ScanResult
		if err := json.Unmarshal(trimmed, &results); err != nil {
			return nil, fmt.Errorf("parse scan results json: %w", err)
		}
		return results, nil
	}

	dec := json.NewDecoder(bytes.NewReader(trimmed))
	results := make([]scanner.ScanResult, 0, 16)
	for {
		var result scanner.ScanResult
		if err := dec.Decode(&result); err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("parse scan results stream: %w", err)
		}
		results = append(results, result)
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("parse scan results stream: no results decoded")
	}
	return results, nil
}

func openScanResults(path string) (io.Reader, func() error, error) {
	if path == "-" {
		return os.Stdin, func() error { return nil }, nil
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open scan results: %w", err)
	}
	return file, file.Close, nil
}
