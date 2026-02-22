package rawsock

import (
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

// ─── Socket ───────────────────────────────────────────────────────────────────

// Socket holds two raw file descriptors: one for sending, one for receiving.
type Socket struct {
	sendFd int
	recvFd int
}

// Open creates and returns a Socket with separate send and recv file descriptors.
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

// Recv reads one packet from the recv socket with the given timeout.
func (s *Socket) Recv(timeout time.Duration) ([]byte, error) {
	tv := syscall.NsecToTimeval(timeout.Nanoseconds())
	if err := syscall.SetsockoptTimeval(s.recvFd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &tv); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, _, err := syscall.Recvfrom(s.recvFd, buf, 0)
	if err != nil {
		return nil, err
	}

	if n < 14 {
		return nil, fmt.Errorf("packet too short")
	}
	return buf[14:n], nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// htons converts a uint16 from host to network byte order.
func htons(i uint16) uint16 {
	b := make([]byte, 2)
	b[0] = byte(i >> 8)
	b[1] = byte(i)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// outboundInterface returns the name of the network interface used for outbound traffic.
func outboundInterface() (string, error) {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "", err
	}
	defer conn.Close()

	localIP := conn.LocalAddr().(*net.UDPAddr).IP
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localIP) {
				return iface.Name, nil
			}
		}
	}
	return "", fmt.Errorf("interface not found")
}

// ─── permission error ─────────────────────────────────────────────────────────

// PermissionErr is returned when raw socket creation fails due to insufficient privileges.
type PermissionErr struct{}

// Error implements the error interface.
func (e *PermissionErr) Error() string {
	return "raw socket requires root privileges\n  hint: run with sudo goscout"
}
