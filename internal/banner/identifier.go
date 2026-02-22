package banner

import (
	"fmt"
	"strings"
)

// ─── identifier ───────────────────────────────────────────────────────────────

// Identify parses the service name and version from a raw banner string.
func Identify(raw string) (service, version string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}

	lower := strings.ToLower(raw)
	switch {
	case strings.Contains(lower, "nginx"):
		service = "nginx"
		version = extractVersion(raw, "nginx/")
	case strings.Contains(lower, "apache"):
		service = "apache"
		version = extractVersion(raw, "Apache/")
	case strings.Contains(lower, "openssh"):
		service = "ssh"
		version = extractVersion(raw, "OpenSSH_")
		if version != "" {
			// normalize "OpenSSH_8.9p1" → "OpenSSH/8.9p1"
			version = strings.ReplaceAll(version, "_", "/")
		}
	case strings.Contains(lower, "microsoft-iis"):
		service = "iis"
		version = extractVersion(raw, "Microsoft-IIS/")
	case strings.HasPrefix(raw, "220") && strings.Contains(lower, "ftp"):
		service = "ftp"
	case strings.HasPrefix(raw, "220") && strings.Contains(lower, "smtp"):
		service = "smtp"
	case strings.HasPrefix(raw, "220") && strings.Contains(lower, "postfix"):
		service = "smtp"
		version = "postfix"
	default:
		parts := strings.Fields(raw)
		if len(parts) > 0 {
			service = strings.ToLower(parts[0])
		}
	}

	return service, version
}

// CVELink returns an NVD search URL for the given service and version.
func CVELink(service, version string) string {
	if service == "" {
		return ""
	}
	if version != "" {
		return fmt.Sprintf("https://nvd.nist.gov/vuln/search/results?query=%s+%s", service, version)
	}
	return fmt.Sprintf("https://nvd.nist.gov/vuln/search/results?query=%s", service)
}

// ─── helper ───────────────────────────────────────────────────────────────────

// extractVersion extracts the version string following prefix in raw.
// Example: "nginx/1.18.0" with prefix "nginx/" → "1.18.0".
func extractVersion(raw, prefix string) string {
	idx := strings.Index(strings.ToLower(raw), strings.ToLower(prefix))
	if idx == -1 {
		return ""
	}
	rest := raw[idx+len(prefix):]

	end := strings.IndexAny(rest, " \t\n\r()")
	if end == -1 {
		return rest
	}
	return rest[:end]
}
