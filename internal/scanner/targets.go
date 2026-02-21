package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

func ParseTargets(r io.Reader) ([]string, error) {
	var targets []string
	seen := make(map[string]bool)
	s := bufio.NewScanner(r)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		expanded, err := expandTarget(line)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", line, err)
		}

		for _, t := range expanded {
			if !seen[t] {
				seen[t] = true
				targets = append(targets, t)
			}
		}
	}

	return targets, s.Err()
}

func expandTarget(target string) ([]string, error) {
	if !strings.Contains(target, "/") {
		return []string{target}, nil
	}

	ip, ipNet, err := net.ParseCIDR(target)
	if err != nil {
		return nil, err
	}

	ones, bits := ipNet.Mask.Size()
	if bits == 0 {
		return nil, fmt.Errorf("unsupported CIDR: %s", target)
	}

	if ones == bits {
		return []string{ip.String()}, nil
	}

	count := 1 << uint(bits-ones)
	if count > 1<<20 {
		return nil, fmt.Errorf("CIDR range too large: %s (%d hosts)", target, count)
	}

	var results []string
	startIP := ipToUint32(ipNet.IP.To4())

	for i := 0; i < count; i++ {
		results = append(results, uint32ToIP(startIP+uint32(i)).String())
	}

	return results, nil
}

func ipToUint32(ip net.IP) uint32 {
	return binary.BigEndian.Uint32(ip)
}

func uint32ToIP(n uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, n)
	return ip
}
