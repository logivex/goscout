package output

import "fmt"

// ─── summary ──────────────────────────────────────────────────────────────────

type Summary struct {
	Scanned  int
	Open     int
	Duration string
	Target   string
}

func PrintSummary(s Summary) {
	if !IsTTY() {
		return
	}
	fmt.Printf("\n")
	colorMuted.Println("─────────────────────────────")
	fmt.Printf("  ")
	colorMuted.Printf("scanned : ")
	colorBold.Printf("%d ports\n", s.Scanned)
	fmt.Printf("  ")
	colorMuted.Printf("open    : ")
	colorOpen.Printf("%d\n", s.Open)
	fmt.Printf("  ")
	colorMuted.Printf("time    : ")
	fmt.Printf("%s\n", s.Duration)
	colorMuted.Println("─────────────────────────────")
	fmt.Println()
}
