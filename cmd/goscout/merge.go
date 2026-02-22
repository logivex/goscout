package main

import (
	"flag"
	"time"

	"github.com/logivex/goscout/config"
)

// mergeConfig builds the final config by merging flag values into cfg.
// Priority: flag > config file > default.
func mergeConfig(cfg config.Config) config.Config {
	if isFlagSet("rate") {
		cfg.Rate = *flagRate
	}
	if isFlagSet("timeout") {
		d, err := time.ParseDuration(*flagTimeout)
		if err == nil {
			cfg.Timeout = d
		}
	}
	if isFlagSet("concurrency") {
		cfg.Concurrency = *flagConcurrency
	}
	if isFlagSet("retries") {
		cfg.Retries = *flagRetries
	}
	if isFlagSet("top") {
		cfg.Top = *flagTop
	}
	if isFlagSet("no-syn") {
		cfg.NoSYN = *flagNoSYN
	}
	if isFlagSet("banner") {
		cfg.Banner = *flagBanner
	}
	if isFlagSet("rdns") {
		cfg.RDNS = *flagRDNS
	}
	if isFlagSet("o") {
		cfg.Output = *flagOutput
	}
	return cfg
}

// isFlagSet reports whether the named flag was explicitly set by the user.
func isFlagSet(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
