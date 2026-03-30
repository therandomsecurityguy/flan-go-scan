package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

type ReportWriter struct {
	OutputDir string
}

func NewReportWriter(outputDir string) (*ReportWriter, error) {
	if outputDir == "" || outputDir == "-" {
		return &ReportWriter{OutputDir: outputDir}, nil
	}
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("create output directory: %w", err)
	}
	return &ReportWriter{OutputDir: outputDir}, nil
}

func (w *ReportWriter) WriteJSON(results []scanner.ScanResult) (err error) {
	writer, closeFn, filename, err := w.open("json")
	if err != nil {
		return err
	}
	defer func() {
		closeErr := closeFn()
		if err == nil && closeErr != nil {
			if filename == "" {
				err = fmt.Errorf("close json writer: %w", closeErr)
			} else {
				err = fmt.Errorf("close %s: %w", filename, closeErr)
			}
		}
	}()
	enc := json.NewEncoder(writer)
	enc.SetIndent("", "  ")
	if err := enc.Encode(results); err != nil {
		if filename == "" {
			return fmt.Errorf("encode json: %w", err)
		}
		return fmt.Errorf("encode json to %s: %w", filename, err)
	}
	return nil
}

func (w *ReportWriter) WriteCSV(results []scanner.ScanResult) (err error) {
	out, closeFn, filename, err := w.open("csv")
	if err != nil {
		return err
	}
	defer func() {
		closeErr := closeFn()
		if err == nil && closeErr != nil {
			if filename == "" {
				err = fmt.Errorf("close csv writer: %w", closeErr)
			} else {
				err = fmt.Errorf("close %s: %w", filename, closeErr)
			}
		}
	}()
	writer := csv.NewWriter(out)
	header := []string{"Host", "Port", "Protocol", "Service", "Version", "Banner", "TLS", "TLS_Version", "TLS_Subject", "TLS_Issuer", "TLS_Expired", "TLS_SelfSigned", "Vulnerabilities"}
	if err := writer.Write(header); err != nil {
		if filename == "" {
			return fmt.Errorf("write csv header: %w", err)
		}
		return fmt.Errorf("write csv header to %s: %w", filename, err)
	}
	for _, res := range results {
		tlsEnabled := "false"
		tlsVersion := ""
		tlsSubject := ""
		tlsIssuer := ""
		tlsExpired := ""
		tlsSelfSigned := ""
		if res.TLS != nil {
			tlsEnabled = "true"
			tlsVersion = res.TLS.Version
			tlsSubject = res.TLS.Subject
			tlsIssuer = res.TLS.Issuer
			tlsExpired = fmt.Sprintf("%v", res.TLS.Expired)
			tlsSelfSigned = fmt.Sprintf("%v", res.TLS.SelfSigned)
		}
		if err := writer.Write([]string{
			res.Host,
			fmt.Sprintf("%d", res.Port),
			res.Protocol,
			res.Service,
			res.Version,
			res.Banner,
			tlsEnabled,
			tlsVersion,
			tlsSubject,
			tlsIssuer,
			tlsExpired,
			tlsSelfSigned,
			strings.Join(res.Vulnerabilities, ";"),
		}); err != nil {
			if filename == "" {
				return fmt.Errorf("write csv row: %w", err)
			}
			return fmt.Errorf("write csv row to %s: %w", filename, err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		if filename == "" {
			return fmt.Errorf("flush csv writer: %w", err)
		}
		return fmt.Errorf("flush csv writer for %s: %w", filename, err)
	}
	return nil
}

func (w *ReportWriter) open(ext string) (io.Writer, func() error, string, error) {
	if w.OutputDir == "" || w.OutputDir == "-" {
		return os.Stdout, func() error { return nil }, "", nil
	}
	filename := filepath.Join(w.OutputDir, fmt.Sprintf("scan-%s.%s", time.Now().Format("20060102-150405"), ext))
	file, err := os.Create(filename)
	if err != nil {
		return nil, nil, "", fmt.Errorf("create %s: %w", filename, err)
	}
	return file, file.Close, filename, nil
}

type JSONLWriter struct {
	mu       sync.Mutex
	enc      *json.Encoder
	w        io.WriteCloser
	Filename string
}

func NewJSONLWriter(outputDir string) (*JSONLWriter, error) {
	var w io.WriteCloser
	var filename string
	if outputDir == "" || outputDir == "-" {
		w = os.Stdout
	} else {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			return nil, fmt.Errorf("create output directory: %w", err)
		}
		filename = filepath.Join(outputDir, fmt.Sprintf("scan-%s.jsonl", time.Now().Format("20060102-150405")))
		f, err := os.Create(filename)
		if err != nil {
			return nil, fmt.Errorf("create %s: %w", filename, err)
		}
		w = f
	}
	return &JSONLWriter{enc: json.NewEncoder(w), w: w, Filename: filename}, nil
}

func (jw *JSONLWriter) WriteResult(result scanner.ScanResult) error {
	jw.mu.Lock()
	defer jw.mu.Unlock()
	return jw.enc.Encode(result)
}

func (jw *JSONLWriter) Close() error {
	if jw.w != os.Stdout {
		return jw.w.Close()
	}
	return nil
}
