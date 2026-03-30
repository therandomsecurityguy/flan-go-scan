package scanner

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

const maxTargetScannerTokenSize = 1024 * 1024

type EndpointTarget struct {
	Host       string
	Port       int
	Kubernetes []KubernetesOrigin
}

func ParseTargets(r io.Reader) ([]string, error) {
	var targets []string
	seen := make(map[string]bool)
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), maxTargetScannerTokenSize)

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

func ParseEndpointTargets(r io.Reader) ([]EndpointTarget, error) {
	var targets []EndpointTarget
	seen := make(map[string]bool)
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), maxTargetScannerTokenSize)

	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}

		host, port, err := splitEndpointTarget(line)
		if err != nil {
			return nil, fmt.Errorf("invalid target %q: %w", line, err)
		}
		key := normalizedEndpointKey(host, port)
		if seen[key] {
			continue
		}
		seen[key] = true
		targets = append(targets, EndpointTarget{Host: host, Port: port})
	}

	return targets, s.Err()
}

func splitEndpointTarget(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("invalid port %q: %w", portStr, err)
	}
	if port < 1 || port > 65535 {
		return "", 0, fmt.Errorf("port out of range: %d", port)
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", 0, fmt.Errorf("empty host")
	}
	if net.ParseIP(host) == nil {
		host = strings.TrimSuffix(strings.ToLower(host), ".")
	}
	return host, port, nil
}

func normalizedEndpointKey(host string, port int) string {
	return net.JoinHostPort(host, strconv.Itoa(port))
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

	if ipNet.IP.To4() == nil {
		if ones == bits {
			return []string{ip.String()}, nil
		}
		return nil, fmt.Errorf("IPv6 CIDR ranges are not supported: %s", target)
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
