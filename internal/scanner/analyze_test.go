package scanner

import (
	"testing"

	"github.com/togethercomputer/together-go"
)

func TestChoiceContentPrefersMessageContent(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Content: "summary",
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
		Text:    "summary",
	}

	if got := choiceContent(choice); got != "summary" {
		t.Fatalf("unexpected content: %q", got)
	}
}

func TestChoiceContentFallsBackToReasoning(t *testing.T) {
	choice := together.ChatCompletionChoice{
		Message: together.ChatCompletionChoiceMessage{
			Reasoning: "summary",
		},
	}

	if got := choiceContent(choice); got != "summary" {
		t.Fatalf("unexpected content: %q", got)
	}
}
