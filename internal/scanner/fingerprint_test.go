package scanner

import "testing"

func TestFingerprintAddrSupportsIPv6(t *testing.T) {
	addr, err := fingerprintAddr("2001:db8::1", 443)
	if err != nil {
		t.Fatalf("fingerprintAddr returned error: %v", err)
	}
	if got := addr.String(); got != "[2001:db8::1]:443" {
		t.Fatalf("unexpected addr: %s", got)
	}
}
