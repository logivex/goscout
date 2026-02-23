//go:build linux

package rawsock

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Socket holds two file descriptors:
//   - sendFd: AF_INET SOCK_RAW for sending SYN packets
//   - recvFd: AF_PACKET SOCK_RAW for receiving all incoming frames
type Socket struct {
	sendFd int
	recvFd int
}

// Open creates send and receive sockets and attaches a BPF filter to the
// receive socket so only TCP SYN-ACK / RST packets destined for our
// ephemeral port range reach userspace.
func Open() (*Socket, error) {
	sendFd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		if err == syscall.EPERM {
			return nil, &PermissionErr{}
		}
		return nil, err
	}
	if err := syscall.SetsockoptInt(sendFd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		syscall.Close(sendFd)
		return nil, err
	}

	recvFd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_IP)))
	if err != nil {
		syscall.Close(sendFd)
		if err == syscall.EPERM {
			return nil, &PermissionErr{}
		}
		return nil, err
	}

	// Attach BPF filter: accept only TCP SYN-ACK or RST packets whose
	// destination port falls in the ephemeral range [49152, 65535].
	if err := attachScanFilter(recvFd, 49152); err != nil {
		syscall.Close(sendFd)
		syscall.Close(recvFd)
		return nil, fmt.Errorf("bpf attach: %w", err)
	}

	return &Socket{sendFd: sendFd, recvFd: recvFd}, nil
}

// Close releases both file descriptors.
func (s *Socket) Close() error {
	syscall.Close(s.recvFd)
	return syscall.Close(s.sendFd)
}

// Send transmits a raw packet to dst.
func (s *Socket) Send(dst net.IP, packet []byte) error {
	addr := &syscall.SockaddrInet4{}
	copy(addr.Addr[:], dst.To4())
	return syscall.Sendto(s.sendFd, packet, 0, addr)
}

// Recv reads the next packet from the receive socket.
// It strips the 14-byte Ethernet header added by AF_PACKET.
func (s *Socket) Recv(timeout time.Duration) ([]byte, error) {
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(s.recvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}

	buf := make([]byte, 65536)
	n, _, err := syscall.Recvfrom(s.recvFd, buf, 0)
	if err != nil {
		return nil, err
	}
	if n < 14 {
		return nil, fmt.Errorf("packet too short: %d bytes", n)
	}
	return buf[14:n], nil
}

// ── BPF filter ───────────────────────────────────────────────────────────────
//
// Packet layout (AF_PACKET, Ethernet frame + IPv4, standard IHL=5):
//
//	[12:14]  EtherType  → must be 0x0800 (IPv4)
//	[23]     IP Proto   → must be 0x06   (TCP)
//	[36:38]  TCP DstPort → must be >= minPort
//	[47]     TCP Flags  → must have RST(0x04) or SYN+ACK(0x12) set
//
// Offsets: Ethernet(14) + IP header(20) + TCP dst port offset(2) = 36
//          Ethernet(14) + IP header(20) + TCP flags offset(13)   = 47

// attachScanFilter builds and attaches a BPF program to fd.
// Only TCP SYN-ACK or RST packets with dst port >= minPort pass through.
func attachScanFilter(fd int, minPort uint16) error {
	filter := []unix.SockFilter{
		// [0] load EtherType (half-word at offset 12)
		{Code: 0x28, K: 12},
		// [1] keep if IPv4 (0x0800), else DROP
		{Code: 0x15, Jt: 0, Jf: 6, K: 0x0800},
		// [2] load IP Protocol (byte at offset 23)
		{Code: 0x30, K: 23},
		// [3] keep if TCP (0x06), else DROP
		{Code: 0x15, Jt: 0, Jf: 4, K: 0x06},
		// [4] load TCP dst port (half-word at offset 36)
		{Code: 0x28, K: 36},
		// [5] keep if >= minPort, else DROP
		{Code: 0x35, Jt: 0, Jf: 2, K: uint32(minPort)},
		// [6] load TCP flags (byte at offset 47)
		{Code: 0x30, K: 47},
		// [7] RST bit (0x04) set? yes → ACCEPT, no → fall through
		{Code: 0x45, Jt: 1, Jf: 0, K: 0x04},
		// [8] SYN+ACK (0x12) set? yes → ACCEPT, no → DROP
		{Code: 0x45, Jt: 0, Jf: 1, K: 0x12},
		// [9] ACCEPT
		{Code: 0x06, K: 0xFFFF},
		// [10] DROP
		{Code: 0x06, K: 0},
	}

	prog := &unix.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	return unix.SetsockoptSockFprog(fd, unix.SOL_SOCKET, unix.SO_ATTACH_FILTER, prog)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// htons converts a uint16 to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	b[0] = byte(i >> 8)
	b[1] = byte(i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// ── PermissionErr ─────────────────────────────────────────────────────────────

// PermissionErr is returned when raw socket creation fails due to insufficient privileges.
type PermissionErr struct{}

func (e *PermissionErr) Error() string {
	return "raw socket requires root privileges\n  hint: run with sudo goscout"
}
