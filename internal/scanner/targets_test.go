package scanner

import (
	"strings"
	"testing"
)

func TestParseTargets(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    int
		wantErr bool
	}{
		{
			name:  "plain IPs",
			input: "192.168.1.1\n10.0.0.1\n",
			want:  2,
		},
		{
			name:  "hostname",
			input: "example.com\n",
			want:  1,
		},
		{
			name:  "cidr /24",
			input: "10.0.0.0/24\n",
			want:  256,
		},
		{
			name:  "cidr /32",
			input: "10.0.0.5/32\n",
			want:  1,
		},
		{
			name:  "mixed",
			input: "192.168.1.1\nexample.com\n10.0.0.0/30\n",
			want:  6,
		},
		{
			name:  "dedup",
			input: "10.0.0.1\n10.0.0.1\n",
			want:  1,
		},
		{
			name:  "empty lines",
			input: "\n\n192.168.1.1\n\n",
			want:  1,
		},
		{
			name:    "invalid cidr",
			input:   "not-a-cidr/24\n",
			wantErr: true,
		},
		{
			name:    "cidr too large",
			input:   "10.0.0.0/8\n",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseTargets(strings.NewReader(tt.input))
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr = %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(got) != tt.want {
				t.Fatalf("got %d targets, want %d", len(got), tt.want)
			}
		})
	}
}
