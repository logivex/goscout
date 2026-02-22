package portscan

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/logivex/goscout/pkg/rawsock"
)

const readTimeout = 100 * time.Millisecond

// ─── receiver ─────────────────────────────────────────────────────────────────

// Receiver reads incoming packets and records port states via Tracker.
type Receiver struct {
	sock    *rawsock.Socket
	target  net.IP
	srcPort int
	tracker *Tracker
	stopped chan struct{}
}

// NewReceiver creates a Receiver bound to the given socket, target, and tracker.
func NewReceiver(sock *rawsock.Socket, target net.IP, srcPort int, tracker *Tracker) *Receiver {
	return &Receiver{
		sock:    sock,
		target:  target,
		srcPort: srcPort,
		tracker: tracker,
		stopped: make(chan struct{}),
	}
}

// Run starts the receive loop in a background goroutine.
func (r *Receiver) Run() {
	go func() {
		for {
			select {
			case <-r.stopped:
				return
			default:
				r.receive()
			}
		}
	}()
}

// Stop signals the receive loop to exit and waits for it to finish.
func (r *Receiver) Stop() {
	close(r.stopped)
	time.Sleep(200 * time.Millisecond)
}

func (r *Receiver) receive() {
	buf, err := r.sock.Recv(readTimeout)
	if err != nil {
		return
	}

	// check for stop signal before processing
	select {
	case <-r.stopped:
		return
	default:
	}

	result, ok := r.parse(buf)
	if !ok {
		return
	}
	r.tracker.Add(result)
}

// parse decodes a raw packet and returns the port scan result.
func (r *Receiver) parse(buf []byte) (Result, bool) {
	if len(buf) < 40 {
		return Result{}, false
	}

	ipHeaderLen := int(buf[0]&0x0f) * 4
	if len(buf) < ipHeaderLen+20 {
		return Result{}, false
	}

	srcIP := net.IP(buf[12:16])
	if !srcIP.Equal(r.target) {
		return Result{}, false
	}

	tcp := buf[ipHeaderLen:]
	dstPort := int(binary.BigEndian.Uint16(tcp[2:4]))
	if dstPort != r.srcPort {
		return Result{}, false
	}

	srcPort := int(binary.BigEndian.Uint16(tcp[0:2]))
	flags := tcp[13]
	synAck := flags&0x12 == 0x12
	rst := flags&0x04 != 0

	if synAck {
		return Result{Port: srcPort, State: StateOpen}, true
	}
	if rst {
		return Result{Port: srcPort, State: StateClosed}, true
	}
	return Result{}, false
}
