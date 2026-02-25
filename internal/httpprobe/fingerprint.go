package httpprobe

import (
	"net/http"
	"strings"
)

// fingerprint checks both response headers and HTML body for known technologies.
// It returns a deduplicated list of technology names.
func fingerprint(headers http.Header, body string) []string {
	seen := make(map[string]bool)
	var tech []string

	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			tech = append(tech, name)
		}
	}

	// CDN / WAF — headers
	headerChecks := []struct {
		header string
		label  string
	}{
		{"CF-Ray", "Cloudflare"},
		{"X-Sucuri-ID", "Sucuri"},
		{"X-Sucuri-Cache", "Sucuri"},
		{"X-Akamai-Transformed", "Akamai"},
		{"X-Fastly-Request-ID", "Fastly"},
		{"X-Served-By", "Fastly"},
		{"X-Azure-Ref", "Azure"},
		{"X-Amz-Cf-Id", "CloudFront"},
		{"X-Amz-Request-Id", "AWS"},
		{"X-Powered-By", ""},
		{"X-Generator", ""},
		{"X-Drupal-Cache", "Drupal"},
		{"X-Drupal-Dynamic-Cache", "Drupal"},
		{"X-Shopify-Stage", "Shopify"},
		{"X-Shopify-Request-Id", "Shopify"},
		{"X-WP-Nonce", "WordPress"},
	}

	for _, c := range headerChecks {
		val := headers.Get(c.header)
		if val == "" {
			continue
		}
		if c.label != "" {
			add(c.label)
		} else {
			// use the header value but clean it up
			clean := strings.SplitN(val, ";", 2)[0]
			clean = strings.TrimSpace(clean)
			if clean != "" {
				add(clean)
			}
		}
	}

	// Server header fingerprinting
	server := strings.ToLower(headers.Get("Server"))
	switch {
	case strings.Contains(server, "nginx"):
		add("Nginx")
	case strings.Contains(server, "apache"):
		add("Apache")
	case strings.Contains(server, "iis"):
		add("IIS")
	case strings.Contains(server, "caddy"):
		add("Caddy")
	case strings.Contains(server, "lighttpd"):
		add("Lighttpd")
	case strings.Contains(server, "openresty"):
		add("OpenResty")
	case strings.Contains(server, "gunicorn"):
		add("Gunicorn")
	case strings.Contains(server, "envoy"):
		add("Envoy")
	}

	// HTML body fingerprinting
	lower := strings.ToLower(body)
	bodyChecks := []struct {
		pattern string
		label   string
	}{
		{"wp-content/", "WordPress"},
		{"wp-includes/", "WordPress"},
		{"drupal.org", "Drupal"},
		{"joomla", "Joomla"},
		{"laravel", "Laravel"},
		{"rails", "Rails"},
		{"react", "React"},
		{"ng-version", "Angular"},
		{"__next/", "Next.js"},
		{"nuxt", "Nuxt.js"},
		{"gatsby", "Gatsby"},
		{"shopify.com/s/files", "Shopify"},
		{"squarespace.com", "Squarespace"},
		{"wix.com", "Wix"},
		{"hubspot", "HubSpot"},
		{"gtm.js", "Google Tag Manager"},
		{"recaptcha", "reCAPTCHA"},
	}

	for _, c := range bodyChecks {
		if strings.Contains(lower, c.pattern) {
			add(c.label)
		}
	}

	// WAF detection from body
	wafChecks := []struct {
		pattern string
		label   string
	}{
		{"request blocked", "WAF"},
		{"access denied", "WAF"},
		{"cloudflare ray id", "Cloudflare"},
		{"sucuri website firewall", "Sucuri WAF"},
		{"barracuda networks", "Barracuda WAF"},
		{"fortigate", "Fortinet WAF"},
	}

	for _, c := range wafChecks {
		if strings.Contains(lower, c.pattern) {
			add(c.label)
		}
	}

	return tech
}
