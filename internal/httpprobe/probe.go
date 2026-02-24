package httpprobe

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// Result holds the HTTP probe outcome for a single host:port.
type Result struct {
	URL        string
	StatusCode int
	Title      string
	Server     string
	Redirect   string
	Tech       []string
}

// Prober performs HTTP and HTTPS probes.
type Prober struct {
	client  *http.Client
	timeout time.Duration
}

// New returns a Prober with the given timeout.
// TLS verification is skipped — common in recon scenarios.
func New(timeout time.Duration) *Prober {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return &Prober{client: client, timeout: timeout}
}

// Probe sends HTTP requests to host:port and returns the first successful result.
// Both HTTP and HTTPS are tried in parallel; the first success wins.
func (p *Prober) Probe(host string, port int) (*Result, error) {
	schemes := []string{"http", "https"}
	if port == 443 || port == 8443 {
		schemes = []string{"https", "http"}
	}

	success := make(chan *Result, len(schemes))
	failure := make(chan error, len(schemes))

	for _, scheme := range schemes {
		go func(s string) {
			url := fmt.Sprintf("%s://%s:%d", s, host, port)
			resp, err := p.client.Get(url)
			if err != nil {
				failure <- err
				return
			}
			defer resp.Body.Close()

			r := &Result{
				URL:        url,
				StatusCode: resp.StatusCode,
				Server:     resp.Header.Get("Server"),
			}
			if loc := resp.Header.Get("Location"); loc != "" {
				r.Redirect = loc
			}
			r.Tech = extractTech(resp.Header)

			body := make([]byte, 4096)
			n, _ := resp.Body.Read(body)
			r.Title = extractTitle(string(body[:n]))

			success <- r
		}(scheme)
	}

	var lastErr error
	for i := 0; i < len(schemes); i++ {
		select {
		case r := <-success:
			return r, nil
		case err := <-failure:
			lastErr = err
		}
	}
	return nil, lastErr
}

// extractTitle parses the <title> tag from HTML.
func extractTitle(body string) string {
	lower := strings.ToLower(body)
	start := strings.Index(lower, "<title>")
	if start == -1 {
		return ""
	}
	start += 7
	end := strings.Index(lower[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(body[start : start+end])
	if len(title) > 80 {
		title = title[:80]
	}
	return title
}

// extractTech identifies technologies from response headers.
func extractTech(headers http.Header) []string {
	var tech []string

	checks := map[string]string{
		"X-Powered-By":      "",
		"X-Generator":       "",
		"X-Drupal-Cache":    "Drupal",
		"X-Wordpress-Cache": "WordPress",
		"CF-Ray":            "Cloudflare",
		"X-Shopify-Stage":   "Shopify",
	}

	for header, label := range checks {
		if val := headers.Get(header); val != "" {
			if label != "" {
				tech = append(tech, label)
			} else {
				tech = append(tech, val)
			}
		}
	}

	return tech
}
