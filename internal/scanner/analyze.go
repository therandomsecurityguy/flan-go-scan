package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/togethercomputer/together-go"
	"github.com/togethercomputer/together-go/option"
)

type AnalysisResult struct {
	Timestamp string          `json:"timestamp"`
	Model     string          `json:"model"`
	Analysis  string          `json:"analysis"`
	Usage     *AnalysisUsage  `json:"usage,omitempty"`
}

type AnalysisUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

const systemPrompt = `You are a security expert analyzing network scan results. For each finding, provide:

1. Severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
2. What was found and why it matters
3. Specific remediation steps

Prioritize findings by risk. Be concise and actionable. Focus on:
- Outdated software versions with known CVEs
- Weak TLS configurations (deprecated versions, weak ciphers)
- Exposed services that shouldn't be public
- Missing security headers
- Password authentication enabled on SSH
- Default credentials risk

Do not repeat raw scan data. Summarize and analyze.`

func Analyze(ctx context.Context, results []ScanResult, outputDir string) (*AnalysisResult, error) {
	apiKey := os.Getenv("TOGETHER_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("TOGETHER_API_KEY not set")
	}

	client := together.NewClient(option.WithAPIKey(apiKey))

	summary := buildSummary(results)
	slog.Info("sending scan results to Together AI for analysis", "services", len(results))

	resp, err := client.Chat.Completions.New(ctx, together.ChatCompletionNewParams{
		Model: "deepseek-ai/DeepSeek-V3.1",
		Messages: []together.ChatCompletionNewParamsMessageUnion{
			{
				OfChatCompletionNewsMessageChatCompletionSystemMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionSystemMessageParam{
					Role:    "system",
					Content: systemPrompt,
				},
			},
			{
				OfChatCompletionNewsMessageChatCompletionUserMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionUserMessageParam{
					Role: "user",
					Content: together.ChatCompletionNewParamsMessageChatCompletionUserMessageParamContentUnion{
						OfString: together.String(fmt.Sprintf("Analyze these network scan results:\n\n%s", summary)),
					},
				},
			},
		},
		MaxTokens:   together.Int(2000),
		Temperature: together.Float(0.3),
	})
	if err != nil {
		return nil, fmt.Errorf("together API call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return nil, fmt.Errorf("no response from model")
	}

	analysis := &AnalysisResult{
		Timestamp: time.Now().Format(time.RFC3339),
		Model:     "deepseek-ai/DeepSeek-V3.1",
		Analysis:  resp.Choices[0].Message.Content,
	}

	if resp.Usage.TotalTokens > 0 {
		analysis.Usage = &AnalysisUsage{
			PromptTokens:     resp.Usage.PromptTokens,
			CompletionTokens: resp.Usage.CompletionTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		}
	}

	if outputDir != "" && outputDir != "-" {
		filename := filepath.Join(outputDir, fmt.Sprintf("analysis-%s.json", time.Now().Format("20060102-150405")))
		data, _ := json.MarshalIndent(analysis, "", "  ")
		if err := os.WriteFile(filename, data, 0600); err != nil {
			slog.Warn("failed to save analysis", "err", err)
		} else {
			slog.Info("analysis saved", "path", filename)
		}
	}

	return analysis, nil
}

func buildSummary(results []ScanResult) string {
	var b strings.Builder

	hosts := make(map[string]bool)
	for _, r := range results {
		hosts[r.Host] = true
	}
	fmt.Fprintf(&b, "Scan summary: %d services found across %d hosts\n\n", len(results), len(hosts))

	for _, r := range results {
		fmt.Fprintf(&b, "Host: %s Port: %d Service: %s", r.Host, r.Port, r.Service)
		if r.Version != "" {
			fmt.Fprintf(&b, " Version: %s", r.Version)
		}
		if r.CDN != "" {
			fmt.Fprintf(&b, " CDN: %s", r.CDN)
		}
		b.WriteString("\n")

		if r.TLS != nil {
			fmt.Fprintf(&b, "  TLS: %s %s", r.TLS.Version, r.TLS.CipherSuite)
			if r.TLS.Expired {
				b.WriteString(" [EXPIRED]")
			}
			if r.TLS.SelfSigned {
				b.WriteString(" [SELF-SIGNED]")
			}
			fmt.Fprintf(&b, " Issuer: %s", r.TLS.Issuer)
			b.WriteString("\n")
		}

		if len(r.Vulnerabilities) > 0 {
			fmt.Fprintf(&b, "  CVEs: %s\n", strings.Join(r.Vulnerabilities, ", "))
		}

		if r.Metadata != nil {
			var meta map[string]interface{}
			if json.Unmarshal(r.Metadata, &meta) == nil {
				if techs, ok := meta["technologies"]; ok {
					fmt.Fprintf(&b, "  Technologies: %v\n", techs)
				}
				if algo, ok := meta["algo"]; ok {
					fmt.Fprintf(&b, "  SSH Algorithms: %v\n", algo)
				}
				if pwAuth, ok := meta["passwordAuthEnabled"]; ok {
					fmt.Fprintf(&b, "  Password Auth: %v\n", pwAuth)
				}
			}
		}
	}

	return b.String()
}
