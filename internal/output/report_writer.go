package output

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/therandomsecurityguy/flan-go-scan/internal/scanner"
)

type ReportWriter struct {
	OutputDir string
}

func NewReportWriter(outputDir string) *ReportWriter {
	os.MkdirAll(outputDir, 0755)
	return &ReportWriter{OutputDir: outputDir}
}

func (w *ReportWriter) WriteJSON(results []scanner.ScanResult) error {
	filename := filepath.Join(w.OutputDir, fmt.Sprintf("scan-%s.json", time.Now().Format("20060102-150405")))
	file, _ := os.Create(filename)
	defer file.Close()
	enc := json.NewEncoder(file)
	enc.SetIndent("", "  ")
	return enc.Encode(results)
}

func (w *ReportWriter) WriteCSV(results []scanner.ScanResult) error {
	filename := filepath.Join(w.OutputDir, fmt.Sprintf("scan-%s.csv", time.Now().Format("20060102-150405")))
	file, _ := os.Create(filename)
	defer file.Close()
	writer := csv.NewWriter(file)
	defer writer.Flush()
	header := []string{"Host", "Port", "Protocol", "Service", "Banner", "TLS", "Vulnerabilities"}
	writer.Write(header)
	for _, res := range results {
		writer.Write([]string{
			res.Host,
			fmt.Sprintf("%d", res.Port),
			res.Protocol,
			res.Service,
			res.Banner,
			fmt.Sprintf("%v", res.TLS),
			strings.Join(res.Vulnerabilities, ";"),
		})
	}
	return nil
}
