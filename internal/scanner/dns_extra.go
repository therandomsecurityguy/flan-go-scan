package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

const defaultDNSResolver = "8.8.8.8:53"

func normalizeResolver(resolver string) string {
	resolver = strings.TrimSpace(resolver)
	if resolver == "" {
		return defaultDNSResolver
	}
	if !strings.Contains(resolver, ":") {
		return net.JoinHostPort(resolver, "53")
	}
	return resolver
}

func LookupPTR(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	for i, name := range names {
		names[i] = strings.TrimSuffix(name, ".")
	}
	return names
}

func LookupASN(ctx context.Context, ip string, timeout time.Duration, resolver string) (asn, org string) {
	reversed, err := reverseIP(ip)
	if err != nil {
		return "", ""
	}

	values, err := lookupTXTRecord(ctx, reversed+".origin.asn.cymru.com", timeout, resolver)
	if err != nil {
		return "", ""
	}
	asn, org = parseTeamCymruOriginTXT(values)
	return asn, org
}

func lookupTXTRecord(ctx context.Context, query string, timeout time.Duration, resolver string) ([]string, error) {
	client := new(dns.Client)
	client.Timeout = timeout
	message := new(dns.Msg)
	message.SetQuestion(dns.Fqdn(query), dns.TypeTXT)
	message.RecursionDesired = true

	if ctx == nil {
		ctx = context.Background()
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	response, _, err := client.ExchangeContext(queryCtx, message, normalizeResolver(resolver))
	if err != nil || response == nil {
		return nil, err
	}

	var values []string
	for _, answer := range response.Answer {
		txt, ok := answer.(*dns.TXT)
		if !ok {
			continue
		}
		values = append(values, txt.Txt...)
	}
	return values, nil
}

func parseTeamCymruOriginTXT(values []string) (asn, org string) {
	for _, value := range values {
		parts := splitAndTrim(value, "|")
		if len(parts) == 0 {
			continue
		}
		asn = parts[0]
		if len(parts) >= 6 {
			org = parts[5]
		}
		return asn, org
	}
	return "", ""
}

func splitAndTrim(value, separator string) []string {
	raw := strings.Split(value, separator)
	parts := make([]string, 0, len(raw))
	for _, item := range raw {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			parts = append(parts, trimmed)
		}
	}
	return parts
}

func reverseIP(ip string) (string, error) {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return "", fmt.Errorf("invalid IP")
	}
	if parsed.To4() != nil {
		parts := strings.Split(ip, ".")
		for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
			parts[i], parts[j] = parts[j], parts[i]
		}
		return strings.Join(parts, "."), nil
	}
	full := fmt.Sprintf("%032x", []byte(parsed.To16()))
	runes := []rune(full)
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return strings.Join(strings.Split(string(runes), ""), "."), nil
}
