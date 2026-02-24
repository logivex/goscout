package banner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"time"
)

// Grabber performs TCP banner grabbing with optional TLS support.
type Grabber struct {
	Timeout time.Duration
}

// New returns a Grabber with the given timeout.
func New(timeout time.Duration) *Grabber {
	return &Grabber{Timeout: timeout}
}

// Grab connects to host:port, reads the banner, and identifies the service.
// For ports 443 and 8443 it uses TLS.
func (g *Grabber) Grab(host string, port int) (*Result, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	var (
		conn net.Conn
		err  error
	)

	isTLS := port == 443 || port == 8443
	if isTLS {
		conn, err = tls.DialWithDialer(
			&net.Dialer{Timeout: g.Timeout},
			"tcp",
			addr,
			&tls.Config{InsecureSkipVerify: true},
		)
	} else {
		conn, err = net.DialTimeout("tcp", addr, g.Timeout)
	}
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(g.Timeout))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil && err != io.EOF {
		// nothing sent on connect — probe with HTTP HEAD
		conn.SetDeadline(time.Now().Add(g.Timeout))
		fmt.Fprintf(conn, "HEAD / HTTP/1.0\r\nHost: %s\r\n\r\n", host)
		conn.SetReadDeadline(time.Now().Add(g.Timeout))
		n, err = conn.Read(buf)
		if err != nil && err != io.EOF {
			return nil, err
		}
	}

	raw := string(buf[:n])
	service, version := Identify(raw)

	return &Result{
		Port:    port,
		Raw:     raw,
		Service: service,
		Version: version,
		CVELink: CVELink(service, version),
	}, nil
}
