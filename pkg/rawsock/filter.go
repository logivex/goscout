package rawsock

import (
	"fmt"
	"os/exec"
)

// BlockRST adds an iptables rule to drop outbound RST packets from srcPort.
func BlockRST(srcPort int) error {
	return exec.Command(
		"iptables", "-A", "OUTPUT",
		"-p", "tcp",
		"--sport", fmt.Sprintf("%d", srcPort),
		"--tcp-flags", "RST", "RST",
		"-j", "DROP",
	).Run()
}

// UnblockRST removes the iptables rule added by BlockRST.
func UnblockRST(srcPort int) error {
	return exec.Command(
		"iptables", "-D", "OUTPUT",
		"-p", "tcp",
		"--sport", fmt.Sprintf("%d", srcPort),
		"--tcp-flags", "RST", "RST",
		"-j", "DROP",
	).Run()
}
