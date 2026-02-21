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
	header := []string{"Host", "Port", "Protocol", "Service", "Banner", "TLS", "TLS_Version", "TLS_Subject", "TLS_Issuer", "TLS_Expired", "TLS_SelfSigned", "Vulnerabilities"}
	writer.Write(header)
	for _, res := range results {
		tlsEnabled := "false"
		tlsVersion := ""
		tlsSubject := ""
		tlsIssuer := ""
		tlsExpired := ""
		tlsSelfSigned := ""
		if res.TLS != nil && res.TLS.Enabled {
			tlsEnabled = "true"
			tlsVersion = res.TLS.Version
			tlsSubject = res.TLS.Subject
			tlsIssuer = res.TLS.Issuer
			tlsExpired = fmt.Sprintf("%v", res.TLS.Expired)
			tlsSelfSigned = fmt.Sprintf("%v", res.TLS.SelfSigned)
		}
		writer.Write([]string{
			res.Host,
			fmt.Sprintf("%d", res.Port),
			res.Protocol,
			res.Service,
			res.Banner,
			tlsEnabled,
			tlsVersion,
			tlsSubject,
			tlsIssuer,
			tlsExpired,
			tlsSelfSigned,
			strings.Join(res.Vulnerabilities, ";"),
		})
	}
	return nil
}
