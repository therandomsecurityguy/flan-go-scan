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
	Timestamp string         `json:"timestamp"`
	Model     string         `json:"model"`
	Analysis  string         `json:"analysis"`
	Usage     *AnalysisUsage `json:"usage,omitempty"`
}

type AnalysisUsage struct {
	PromptTokens     int64 `json:"prompt_tokens"`
	CompletionTokens int64 `json:"completion_tokens"`
	TotalTokens      int64 `json:"total_tokens"`
}

const TogetherModel = "Qwen/Qwen3.5-9B"

const briefSystemPrompt = `You are a security expert. Summarize the scan results in 5-7 bullet points:
- Lead with critical/high severity findings; include a one-line remediation for each
- Cover medium severity issues (missing headers, weak TLS, exposed admin interfaces, version disclosure)
- Flag suspicious or non-standard ports by number -- apply known associations (31337 = Back Orifice, 4444 = Metasploit, 9929 = nping-echo, 6666 = IRC/malware)
- Close with one sentence on overall risk posture
Each bullet: what it is, why it matters, what to do. No preamble.`

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
- Unknown or unidentified services: analyze the port number itself for well-known associations (e.g., 31337 = Back Orifice/elite malware, 4444 = Metasploit, 9929 = nping-echo, 6666 = IRC/malware, 1337, etc.) and flag suspicious ports explicitly

Do not repeat raw scan data. Summarize and analyze.`

func ValidateAPIKey() error {
	apiKey := os.Getenv("TOGETHER_API_KEY")
	if apiKey == "" {
		return fmt.Errorf("TOGETHER_API_KEY not set")
	}

	if len(apiKey) < 10 {
		return fmt.Errorf("TOGETHER_API_KEY appears invalid (too short)")
	}

	client := together.NewClient(option.WithAPIKey(apiKey))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := client.Models.List(ctx, together.ModelListParams{})
	if err != nil {
		return fmt.Errorf("failed to validate TOGETHER_API_KEY: %w", err)
	}

	return nil
}

func Analyze(ctx context.Context, results []ScanResult, outputDir string, sc *ScanContext) (*AnalysisResult, error) {
	apiKey := os.Getenv("TOGETHER_API_KEY")
	if apiKey == "" {
		return nil, fmt.Errorf("TOGETHER_API_KEY not set")
	}

	client := together.NewClient(option.WithAPIKey(apiKey))

	summary := buildSummary(results)
	if ctxSummary := BuildContextSummary(sc); ctxSummary != "" {
		summary = ctxSummary + "\n" + summary
	}
	slog.Info("sending scan results to Together AI for analysis", "services", len(results))

	resp, err := client.Chat.Completions.New(ctx, together.ChatCompletionNewParams{
		Model: TogetherModel,
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
		Model:     TogetherModel,
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
		data, err := json.MarshalIndent(analysis, "", "  ")
		if err != nil {
			slog.Warn("failed to marshal analysis", "err", err)
			return analysis, nil
		}
		if err := os.WriteFile(filename, data, 0600); err != nil {
			slog.Warn("failed to save analysis", "err", err)
		} else {
			slog.Info("analysis saved", "path", filename)
		}
	}

	return analysis, nil
}

func AnalyzeBrief(ctx context.Context, results []ScanResult, sc *ScanContext) (string, error) {
	apiKey := os.Getenv("TOGETHER_API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("TOGETHER_API_KEY not set")
	}

	client := together.NewClient(option.WithAPIKey(apiKey))
	summary := buildSummary(results)
	if ctxSummary := BuildContextSummary(sc); ctxSummary != "" {
		summary = ctxSummary + "\n" + summary
	}

	resp, err := client.Chat.Completions.New(ctx, together.ChatCompletionNewParams{
		Model: TogetherModel,
		Messages: []together.ChatCompletionNewParamsMessageUnion{
			{
				OfChatCompletionNewsMessageChatCompletionSystemMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionSystemMessageParam{
					Role:    "system",
					Content: briefSystemPrompt,
				},
			},
			{
				OfChatCompletionNewsMessageChatCompletionUserMessageParam: &together.ChatCompletionNewParamsMessageChatCompletionUserMessageParam{
					Role: "user",
					Content: together.ChatCompletionNewParamsMessageChatCompletionUserMessageParamContentUnion{
						OfString: together.String(fmt.Sprintf("Summarize:\n\n%s", summary)),
					},
				},
			},
		},
		MaxTokens:   together.Int(400),
		Temperature: together.Float(0.2),
	})
	if err != nil {
		return "", fmt.Errorf("together API call failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return "", fmt.Errorf("no response from model")
	}

	return resp.Choices[0].Message.Content, nil
}

func buildSummary(results []ScanResult) string {
	var b strings.Builder

	hosts := make(map[string]bool)
	for _, r := range results {
		key := r.Host
		if r.Hostname != "" {
			key = r.Hostname + "|" + r.Host
		}
		hosts[key] = true
	}
	fmt.Fprintf(&b, "Scan summary: %d services found across %d hosts\n\n", len(results), len(hosts))

	for _, r := range results {
		displayHost := r.Host
		if r.Hostname != "" && r.Hostname != r.Host {
			displayHost = fmt.Sprintf("%s (%s)", r.Hostname, r.Host)
		}
		fmt.Fprintf(&b, "Host: %s Port: %d Service: %s", displayHost, r.Port, r.Service)
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

		if r.PTR != "" {
			fmt.Fprintf(&b, "  PTR: %s\n", r.PTR)
		}
		if r.ASN != "" {
			fmt.Fprintf(&b, "  ASN: AS%s %s\n", r.ASN, r.Org)
		}

		if r.TLSEnum != nil {
			fmt.Fprintf(&b, "  TLS versions supported: %s\n", strings.Join(r.TLSEnum.SupportedVersions, ", "))
			if len(r.TLSEnum.WeakVersions) > 0 {
				fmt.Fprintf(&b, "  Deprecated TLS versions: %s\n", strings.Join(r.TLSEnum.WeakVersions, ", "))
			}
			if len(r.TLSEnum.WeakCiphers) > 0 {
				fmt.Fprintf(&b, "  Weak ciphers: %s\n", strings.Join(r.TLSEnum.WeakCiphers, ", "))
			}
		}

		if len(r.SecurityHeaders) > 0 {
			fmt.Fprintf(&b, "  Security header findings:\n")
			for _, f := range r.SecurityHeaders {
				fmt.Fprintf(&b, "    [%s] %s: %s\n", f.Severity, f.Header, f.Detail)
			}
		}

		if r.App != nil {
			if r.App.Server != "" {
				fmt.Fprintf(&b, "  Server: %s\n", r.App.Server)
			}
			if r.App.PoweredBy != "" {
				fmt.Fprintf(&b, "  Powered-By: %s\n", r.App.PoweredBy)
			}
			if r.App.Generator != "" {
				fmt.Fprintf(&b, "  Generator: %s\n", r.App.Generator)
			}
			if len(r.App.Apps) > 0 {
				fmt.Fprintf(&b, "  Detected apps: %s\n", strings.Join(r.App.Apps, ", "))
			}
		}

		if len(r.Endpoints) > 0 {
			fmt.Fprintf(&b, "  Endpoints:\n")
			for _, ep := range r.Endpoints {
				fmt.Fprintf(&b, "    %d %s", ep.StatusCode, ep.Path)
				if ep.Title != "" {
					fmt.Fprintf(&b, " [%s]", ep.Title)
				}
				if ep.RedirectTo != "" {
					fmt.Fprintf(&b, " -> %s", ep.RedirectTo)
				}
				b.WriteString("\n")
			}
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
