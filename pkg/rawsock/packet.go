package rawsock

import (
	"encoding/binary"
	"math/rand"
	"net"
)

// BuildSYN constructs a complete SYN packet for the given source and destination.
func BuildSYN(srcIP, dstIP net.IP, srcPort, dstPort int) ([]byte, error) {
	tcp := buildTCPHeader(srcIP, dstIP, srcPort, dstPort)
	ip := buildIPHeader(srcIP, dstIP, len(tcp))

	packet := make([]byte, len(ip)+len(tcp))
	copy(packet, ip)
	copy(packet[len(ip):], tcp)

	return packet, nil
}

// ─── IP header ────────────────────────────────────────────────────────────────

func buildIPHeader(src, dst net.IP, payloadLen int) []byte {
	h := make([]byte, 20)

	h[0] = 0x45                                                  // version=4, IHL=5
	h[1] = 0x00                                                  // DSCP/ECN
	binary.BigEndian.PutUint16(h[2:4], uint16(20+payloadLen))    // total length
	binary.BigEndian.PutUint16(h[4:6], uint16(rand.Intn(65535))) // ID
	h[6] = 0x40                                                  // flags: don't fragment
	h[7] = 0x00                                                  // fragment offset
	h[8] = 64                                                    // TTL
	h[9] = 0x06                                                  // protocol: TCP
	// h[10:12] checksum — computed after the rest of the header is filled
	copy(h[12:16], src.To4()) // source IP
	copy(h[16:20], dst.To4()) // destination IP

	// IP checksum
	binary.BigEndian.PutUint16(h[10:12], checksum(h))

	return h
}

// ─── TCP header ───────────────────────────────────────────────────────────────

func buildTCPHeader(src, dst net.IP, srcPort, dstPort int) []byte {
	h := make([]byte, 20)

	binary.BigEndian.PutUint16(h[0:2], uint16(srcPort)) // source port
	binary.BigEndian.PutUint16(h[2:4], uint16(dstPort)) // destination port
	binary.BigEndian.PutUint32(h[4:8], rand.Uint32())   // sequence number
	binary.BigEndian.PutUint32(h[8:12], 0)              // ack number
	h[12] = 0x50                                        // data offset: 5*4=20 bytes
	h[13] = 0x02                                        // flags: SYN
	binary.BigEndian.PutUint16(h[14:16], 65535)         // window size
	// h[16:18] checksum — computed over the pseudo header
	binary.BigEndian.PutUint16(h[18:20], 0) // urgent pointer

	// TCP checksum requires a pseudo header
	binary.BigEndian.PutUint16(h[16:18], tcpChecksum(src, dst, h))

	return h
}

// ─── checksum ─────────────────────────────────────────────────────────────────

// checksum computes the Internet checksum as defined in RFC 1071.
func checksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 != 0 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

// tcpChecksum computes the TCP checksum using a pseudo header.
// Pseudo header layout: src IP + dst IP + zero + protocol + TCP length.
func tcpChecksum(src, dst net.IP, tcpHeader []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpHeader))

	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 0x00
	pseudo[9] = 0x06
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpHeader)))
	copy(pseudo[12:], tcpHeader)

	return checksum(pseudo)
}
