package main

import (
	"flag"
	"fmt"
)

const version = "0.1.0"

// ─── flags ────────────────────────────────────────────────────────────────────

var (
	flagTarget      = flag.String("t", "", "target: IP, domain, CIDR, or file path")
	flagPorts       = flag.String("p", "", "specific ports: 80,443,8080")
	flagTop         = flag.Int("top", 1000, "scan top N ports")
	flagFull        = flag.Bool("full", false, "scan all 65535 ports")
	flagRate        = flag.Int("rate", 500, "packets per second")
	flagTimeout     = flag.String("timeout", "800ms", "per port timeout")
	flagConcurrency = flag.Int("concurrency", 1000, "concurrent ports")
	flagRetries     = flag.Int("retries", 1, "retries per port")
	flagNoSYN       = flag.Bool("no-syn", false, "connect scan instead of SYN")
	flagBanner      = flag.Bool("banner", false, "enable banner grabbing")
	flagRDNS        = flag.Bool("rdns", false, "enable reverse DNS lookup")
	flagOutput      = flag.String("o", "human", "output format: human, json, csv")
	flagFile        = flag.String("f", "", "save output to file")
	flagSilent      = flag.Bool("s", false, "silent mode — results only")
	flagVerbose     = flag.Bool("v", false, "verbose mode")
	flagDebug       = flag.Bool("debug", false, "debug mode")
	flagConfig      = flag.String("config", "", "config file (default: ~/.goscout.yaml)")
	flagVersion     = flag.Bool("version", false, "print version")
)

// ─── help ─────────────────────────────────────────────────────────────────────

// printHelp prints the full usage message to stdout.
func printHelp() {
	fmt.Printf(`goscout v%s — network reconnaissance for bug bounty

USAGE:
  goscout -t <target> [flags]
  echo "1.2.3.4" | goscout [flags]
  cat targets.txt | goscout [flags]

TARGET:
  -t            IP, domain, CIDR, or file path

PORTS:
  -p            specific ports: 80,443,8080
  --top         top N ports (default: 1000)
  --full        all 65535 ports

SCAN:
  --rate        packets per second (default: 500)
  --timeout     per port timeout (default: 800ms)
  --concurrency concurrent ports (default: 1000)
  --retries     retries per port (default: 1)
  --no-syn      connect scan, no root needed

FEATURES:
  --banner      grab service banners
  --rdns        reverse DNS lookup

OUTPUT:
  -o            format: human, json, csv (default: human)
  -f            save to file
  -s            silent mode
  -v            verbose
  --debug       debug mode

EXAMPLES:
  goscout -t example.com --top 1000 --banner --rdns
  goscout -t 1.2.3.4 -p 80,443,8080
  goscout -t targets.txt --full -o json -f out.json
  subfinder -d example.com | goscout --banner -o json
`, version)
}
