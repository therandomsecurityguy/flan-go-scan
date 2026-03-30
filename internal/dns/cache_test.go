package dns

import "testing"

func TestNormalizeResolverAddr(t *testing.T) {
	tests := map[string]string{
		"":                     "",
		"system":               "system",
		"1.1.1.1":              "1.1.1.1:53",
		"1.1.1.1:5353":         "1.1.1.1:5353",
		"2606:4700:4700::1111": "[2606:4700:4700::1111]:53",
	}
	for input, want := range tests {
		if got := normalizeResolverAddr(input); got != want {
			t.Fatalf("normalizeResolverAddr(%q)=%q want %q", input, got, want)
		}
	}
}
