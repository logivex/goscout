package output

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

// ─── colors ───────────────────────────────────────────────────────────────────

var (
	colorOpen     = color.New(color.FgGreen, color.Bold)
	colorClosed   = color.New(color.FgRed)
	colorFiltered = color.New(color.FgYellow)
	colorBanner   = color.New(color.FgYellow)
	colorRDNS     = color.New(color.FgCyan)
	colorMuted    = color.New(color.FgHiBlack)
	colorBold     = color.New(color.Bold)
)

// IsTTY reports whether stdout is a terminal rather than a pipe.
// fatih/color disables itself automatically when output is not a TTY.
func IsTTY() bool {
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

// ─── header ───────────────────────────────────────────────────────────────────

// PrintHeader prints the scan header with target info and column labels.
func PrintHeader(target, ip, version string) {
	if !IsTTY() {
		return
	}
	fmt.Printf("\n")
	colorBold.Printf("goscout v%s", version)
	colorMuted.Printf(" — target: ")
	colorBold.Printf("%s", target)
	if ip != "" && ip != target {
		colorMuted.Printf(" (%s)", ip)
	}
	fmt.Printf("\n\n")
	colorMuted.Printf("%-8s %-8s %-12s %s\n", "PORT", "STATE", "SERVICE", "BANNER")
	colorMuted.Printf("%-8s %-8s %-12s %s\n", "────", "─────", "───────", "──────")
}

// ─── port ─────────────────────────────────────────────────────────────────────

// PrintPort prints a single port result with state, service, banner, and CVE link.
func PrintPort(port int, state, service, banner, cveLink string) {
	portStr := fmt.Sprintf("%d/tcp", port)
	if state == "open" {
		colorOpen.Printf("%-8s %-8s %-12s", portStr, state, service)
		if banner != "" {
			colorBanner.Printf(" %s", banner)
		}
		fmt.Println()
		if cveLink != "" {
			colorMuted.Printf("         → %s\n", cveLink)
		}
	} else if state == "filtered" {
		colorFiltered.Printf("%-8s %-8s\n", portStr, state)
	} else {
		colorClosed.Printf("%-8s %-8s\n", portStr, state)
	}
}

// ─── rdns ─────────────────────────────────────────────────────────────────────

// PrintRDNS prints the reverse DNS result for an IP.
func PrintRDNS(ip, hostname string) {
	fmt.Printf("\n")
	colorMuted.Printf("rdns: ")
	colorRDNS.Printf("%s → %s\n", ip, hostname)
}
