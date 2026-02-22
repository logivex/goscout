package portscan

import "time"

// ─── config ───────────────────────────────────────────────────────────────────

type Config struct {
	Rate        int
	Timeout     time.Duration
	Concurrency int
	Retries     int
	SrcPort     int
}

func DefaultConfig() Config {
	return Config{
		Rate:        500,
		Timeout:     800 * time.Millisecond,
		Concurrency: 1000,
		Retries:     1,
		SrcPort:     54321,
	}
}
