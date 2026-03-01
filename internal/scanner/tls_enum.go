package scanner

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

type TLSEnum struct {
	SupportedVersions []string `json:"supported_versions"`
	WeakVersions      []string `json:"weak_versions,omitempty"`
	CipherSuites      []string `json:"cipher_suites,omitempty"`
	WeakCiphers       []string `json:"weak_ciphers,omitempty"`
}

var tlsVersionList = []struct {
	version uint16
	name    string
	weak    bool
}{
	{tls.VersionTLS10, "TLS1.0", true},
	{tls.VersionTLS11, "TLS1.1", true},
	{tls.VersionTLS12, "TLS1.2", false},
	{tls.VersionTLS13, "TLS1.3", false},
}

func EnumerateTLS(ctx context.Context, host, hostname string, port int, timeout time.Duration, verify bool) *TLSEnum {
	if hostname == "" {
		hostname = host
	}
	addr := tlsAddr(host, port)
	result := &TLSEnum{}
	hasTLS12 := false
	var mu sync.Mutex
	var wg sync.WaitGroup

	versionCh := make(chan struct {
		name    string
		version uint16
		weak    bool
	})

	for _, v := range tlsVersionList {
		wg.Add(1)
		go func(version uint16, name string, weak bool) {
			defer wg.Done()
			if ctx.Err() != nil {
				return
			}
			if probeTLSVersion(addr, hostname, version, timeout, verify) {
				mu.Lock()
				versionCh <- struct {
					name    string
					version uint16
					weak    bool
				}{name, version, weak}
				mu.Unlock()
			}
		}(v.version, v.name, v.weak)
	}

	go func() {
		wg.Wait()
		close(versionCh)
	}()

	for v := range versionCh {
		result.SupportedVersions = append(result.SupportedVersions, v.name)
		if v.weak {
			result.WeakVersions = append(result.WeakVersions, v.name)
		}
		if v.version == tls.VersionTLS12 {
			hasTLS12 = true
		}
	}

	if hasTLS12 {
		cipherSuites := append(tls.CipherSuites(), tls.InsecureCipherSuites()...)
		cipherCh := make(chan string, len(cipherSuites))
		var cipherWG sync.WaitGroup
		const maxParallel = 8
		sem := make(chan struct{}, maxParallel)

		for _, cs := range cipherSuites {
			cipherWG.Add(1)
			go func(cs *tls.CipherSuite) {
				sem <- struct{}{}
				defer func() {
					<-sem
					cipherWG.Done()
				}()
				if ctx.Err() != nil {
					return
				}
				if probeCipher(addr, hostname, cs.ID, timeout, verify) {
					mu.Lock()
					cipherCh <- cs.Name
					mu.Unlock()
				}
			}(cs)
		}

		go func() {
			cipherWG.Wait()
			close(cipherCh)
		}()

		for name := range cipherCh {
			result.CipherSuites = append(result.CipherSuites, name)
			if isWeakCipher(name) {
				result.WeakCiphers = append(result.WeakCiphers, name)
			}
		}
	}

	if len(result.SupportedVersions) == 0 {
		return nil
	}
	return result
}

func probeTLSVersion(addr, hostname string, version uint16, timeout time.Duration, verify bool) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
		MinVersion:         version,
		MaxVersion:         version,
		InsecureSkipVerify: !verify,
		ServerName:         hostname,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func probeCipher(addr, hostname string, cipher uint16, timeout time.Duration, verify bool) bool {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: timeout}, "tcp", addr, &tls.Config{
		MinVersion:         tls.VersionTLS12,
		MaxVersion:         tls.VersionTLS12,
		CipherSuites:       []uint16{cipher},
		InsecureSkipVerify: !verify,
		ServerName:         hostname,
	})
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func tlsAddr(host string, port int) string {
	if strings.Contains(host, ":") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func isWeakCipher(name string) bool {
	upper := strings.ToUpper(name)
	for _, kw := range []string{"RC4", "DES", "EXPORT", "NULL", "ANON", "_CBC_"} {
		if strings.Contains(upper, kw) {
			return true
		}
	}
	return false
}
