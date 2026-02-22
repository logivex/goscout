package portscan

import (
	"net"
	"time"

	"github.com/logivex/goscout/pkg/rawsock"
)

// ─── sender ───────────────────────────────────────────────────────────────────

// Sender transmits SYN packets to target ports at a controlled rate.
type Sender struct {
	sock    *rawsock.Socket
	target  net.IP
	srcPort int
	rate    int // packets per second
}

// NewSender creates a Sender targeting the given IP at the specified rate.
func NewSender(sock *rawsock.Socket, target net.IP, srcPort, rate int) *Sender {
	return &Sender{
		sock:    sock,
		target:  target,
		srcPort: srcPort,
		rate:    rate,
	}
}

// Send transmits a SYN packet to the given port.
func (s *Sender) Send(port int) error {
	packet, err := rawsock.BuildSYN(
		localIP(),
		s.target,
		s.srcPort,
		port,
	)
	if err != nil {
		return err
	}
	return s.sock.Send(s.target, packet)
}

// Delay sleeps between packets to respect the configured rate limit.
func (s *Sender) Delay() {
	if s.rate <= 0 {
		return
	}
	time.Sleep(time.Second / time.Duration(s.rate))
}

// ─── helper ───────────────────────────────────────────────────────────────────

// localIP returns the local IP address used for outbound connections.
func localIP() net.IP {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return net.ParseIP("127.0.0.1")
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP
}
