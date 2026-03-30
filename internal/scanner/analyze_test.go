package scanner

import (
	"strings"
	"testing"

	"github.com/togethercomputer/together-go"
)

func TestChoiceContentPrefersMessageContent(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Content: "<report>summary</report>",
		},
		Text: "fallback",
	}

	if got := choiceContent(choice); got != "summary" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestChoiceContentFallsBackToText(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{},
		Text:    "<report>summary</report>",
	}

	if got := choiceContent(choice); got != "summary" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestChoiceContentDoesNotFallbackToReasoning(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Reasoning: "<report>summary</report>",
		},
	}

	if got := choiceContent(choice); got != "" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestChoiceContentExtractsTaggedReport(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Content: "Thinking Process:\ninternal\n<report>final report</report>",
		},
	}

	if got := choiceContent(choice); got != "final report" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestChoiceContentDropsReasoningOnlyOutput(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Content: "Thinking Process:\n1. inspect\n2. reason\n3. answer later",
		},
	}

	if got := choiceContent(choice); got != "" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestChoiceContentUsesFinalAnswerFallback(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Content: "Analysis:\ninternal\nFinal Answer:\n- HIGH: fix this",
		},
	}

	if got := choiceContent(choice); got != "- HIGH: fix this" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestBuildSummaryIncludesKubernetesOrigins(t *testing.T) {
	summary := buildSummary([]ScanResult{{
		Host:     "69.2.199.151",
		Hostname: "dapperdingo-hn1.cloud.together.ai",
		Port:     6443,
		Service:  "https",
		Kubernetes: []KubernetesOrigin{{
			Cluster:  "dapperdingo",
			Context:  "dapperdingo",
			Kind:     "APIServer",
			Name:     "kubernetes",
			Exposure: "cluster",
		}},
	}})

	if !strings.Contains(summary, "Kubernetes: APIServer kubernetes cluster=dapperdingo exposure=cluster") {
		t.Fatalf("expected kubernetes origin in summary, got %q", summary)
	}
}
