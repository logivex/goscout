package rdns

import (
	"net"
	"strings"
)

// ─── lookup ───────────────────────────────────────────────────────────────────

// Lookup performs a reverse DNS lookup for the given IP.
// If no hostname is found, it returns nil without an error.
func Lookup(ip string) (*Result, error) {
	hostnames, err := net.LookupAddr(ip)
	if err != nil {
		if isNotFound(err) {
			return nil, nil
		}
		return nil, err
	}

	if len(hostnames) == 0 {
		return nil, nil
	}

	hostname := strings.TrimSuffix(hostnames[0], ".")
	return &Result{
		IP:       ip,
		Hostname: hostname,
	}, nil
}

// ─── helper ───────────────────────────────────────────────────────────────────

// isNotFound reports whether err is a DNS "not found" error.
func isNotFound(err error) bool {
	if dnsErr, ok := err.(*net.DNSError); ok {
		return dnsErr.IsNotFound
	}
	return false
}
