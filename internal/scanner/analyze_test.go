package scanner

import (
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

func TestChoiceContentFallsBackToReasoning(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Reasoning: "<report>summary</report>",
		},
	}

	if got := choiceContent(choice); got != "summary" {
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
