package portscan

import "time"

// Config holds tuning parameters for a scan run.
type Config struct {
	Rate        int           // packets per second
	Timeout     time.Duration // wait time for responses after sending
	Concurrency int           // max simultaneous SYN goroutines
	Retries     int           // SYN retries per port
	SrcPort     int           // source port used to filter incoming replies
}

// DefaultConfig returns sensible defaults for most scans.
func DefaultConfig() Config {
	return Config{
		Rate:        500,
		Timeout:     1200 * time.Millisecond,
		Concurrency: 1000,
		Retries:     2,
		SrcPort:     54321,
	}
}
