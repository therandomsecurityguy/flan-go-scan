package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type SRVRecord struct {
	Service  string `json:"service"`
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
}

type SOARecord struct {
	NS      string `json:"ns"`
	MBox    string `json:"mbox"`
	Serial  uint32 `json:"serial"`
	Refresh uint32 `json:"refresh"`
	Retry   uint32 `json:"retry"`
	Expire  uint32 `json:"expire"`
}

type CAARecord struct {
	Tag   string `json:"tag"`
	Value string `json:"value"`
}

type DNSExtra struct {
	PTR []string    `json:"ptr,omitempty"`
	SRV []SRVRecord `json:"srv,omitempty"`
	SOA *SOARecord  `json:"soa,omitempty"`
	CAA []CAARecord `json:"caa,omitempty"`
	ASN string      `json:"asn,omitempty"`
	Org string      `json:"org,omitempty"`
}

func LookupPTR(ip string) []string {
	names, err := net.LookupAddr(ip)
	if err != nil {
		return nil
	}
	for i, n := range names {
		names[i] = strings.TrimSuffix(n, ".")
	}
	return names
}

func LookupSRV(service, proto, domain string) []SRVRecord {
	_, addrs, err := net.LookupSRV(service, proto, domain)
	if err != nil {
		return nil
	}
	records := make([]SRVRecord, 0, len(addrs))
	for _, a := range addrs {
		records = append(records, SRVRecord{
			Service:  fmt.Sprintf("_%s._%s.%s", service, proto, domain),
			Target:   a.Target,
			Port:     a.Port,
			Priority: a.Priority,
			Weight:   a.Weight,
		})
	}
	return records
}

func LookupSOA(domain string, timeout time.Duration) *SOARecord {
	c := new(dns.Client)
	c.Timeout = timeout
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil || r == nil {
		return nil
	}
	for _, ans := range r.Answer {
		if soa, ok := ans.(*dns.SOA); ok {
			return &SOARecord{
				NS:      soa.Ns,
				MBox:    soa.Mbox,
				Serial:  soa.Serial,
				Refresh: soa.Refresh,
				Retry:   soa.Retry,
				Expire:  soa.Expire,
			}
		}
	}
	return nil
}

func LookupCAA(domain string, timeout time.Duration) []CAARecord {
	c := new(dns.Client)
	c.Timeout = timeout
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeCAA)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil || r == nil {
		return nil
	}
	var records []CAARecord
	for _, ans := range r.Answer {
		if caa, ok := ans.(*dns.CAA); ok {
			records = append(records, CAARecord{
				Tag:   caa.Tag,
				Value: caa.Value,
			})
		}
	}
	return records
}

func LookupASN(ctx context.Context, ip string, timeout time.Duration) (asn, org string) {
	reversed, err := reverseIP(ip)
	if err != nil {
		return "", ""
	}
	query := reversed + ".origin.asn.cymru.com"

	c := new(dns.Client)
	c.Timeout = timeout
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(query), dns.TypeTXT)
	m.RecursionDesired = true

	r, _, err := c.Exchange(m, "8.8.8.8:53")
	if err != nil || r == nil {
		return "", ""
	}
	for _, ans := range r.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			for _, s := range txt.Txt {
				parts := strings.Split(s, " | ")
				if len(parts) >= 1 {
					asn = strings.TrimSpace(parts[0])
				}
				if len(parts) >= 3 {
					org = strings.TrimSpace(parts[2])
				}
				return asn, org
			}
		}
	}
	return "", ""
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
