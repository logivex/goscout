package main

import (
	"bufio"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/logivex/goscout/config"
	"github.com/logivex/goscout/internal/banner"
	"github.com/logivex/goscout/internal/errors"
	"github.com/logivex/goscout/internal/output"
	"github.com/logivex/goscout/internal/portscan"
	"github.com/logivex/goscout/internal/rdns"
)

// ─── input ────────────────────────────────────────────────────────────────────

type inputMode int

const (
	modeFlag inputMode = iota
	modePipe
	modeFile
)

type input struct {
	mode    inputMode
	targets []string
}

// ─── run ──────────────────────────────────────────────────────────────────────

// run is the main entry point after flag parsing.
func run() {
	flag.Usage = printHelp
	flag.Parse()

	if *flagVersion {
		fmt.Printf("goscout v%s\n", version)
		os.Exit(0)
	}

	in, err := detectInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(2)
	}

	if in == nil {
		printHelp()
		os.Exit(0)
	}

	cfg, err := config.Load(*flagConfig)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: cannot load config: %s\n", err)
		os.Exit(2)
	}
	cfg = mergeConfig(cfg)

	if *flagDebug {
		fmt.Fprintf(os.Stderr, "[debug] targets: %v\n", in.targets)
		fmt.Fprintf(os.Stderr, "[debug] banner: %v | rdns: %v | no-syn: %v\n", cfg.Banner, cfg.RDNS, cfg.NoSYN)
		fmt.Fprintf(os.Stderr, "[debug] rate: %d | timeout: %s | concurrency: %d\n",
			cfg.Rate, cfg.Timeout, cfg.Concurrency)
	}

	// resolve port list
	ports, err := resolvePorts(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(2)
	}

	// expand CIDRs and prepare targets
	expanded, err := expandTargets(in.targets)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(2)
	}

	if *flagDebug {
		n := len(expanded)
		show := expanded
		if n > 5 {
			show = expanded[:5]
		}
		fmt.Fprintf(os.Stderr, "[debug] expanded %d targets: %v\n", n, show)
	}

	// run each target concurrently; printMu serializes output.
	var wg sync.WaitGroup
	var printMu sync.Mutex
	sem := make(chan struct{}, 10)

	var totalOpen int64
	for _, target := range expanded {
		wg.Add(1)
		sem <- struct{}{}
		go func(t string) {
			defer wg.Done()
			defer func() { <-sem }()
			printMu.Lock()
			err := scanTarget(t, ports, cfg, &printMu)
			printMu.Unlock()
			if err != nil {
				var permErr *errors.PermissionError
				if isPermErr(err, permErr) {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					os.Exit(3)
				}
				// "no open ports" is not an error worth logging.
				if err.Error() != "no open ports found" {
					fmt.Fprintf(os.Stderr, "error [%s]: %s\n", t, err)
				}
			} else {
				atomic.AddInt64(&totalOpen, 1)
			}
		}(target)
	}
	wg.Wait()

	if totalOpen == 0 {
		os.Exit(1)
	}
}

// ─── scan target ──────────────────────────────────────────────────────────────

// scanTarget resolves, scans, and outputs results for a single target.
func scanTarget(target string, ports []int, cfg config.Config, mu *sync.Mutex) error {
	// resolve domain to IP
	ip, err := resolveTarget(target)
	if err != nil {
		return err
	}

	if !*flagSilent && cfg.Output == "human" {
		output.PrintHeader(target, ip.String(), version)
	}

	start := time.Now()

	// port scan
	scanCfg := portscan.Config{
		Rate:        cfg.Rate,
		Timeout:     cfg.Timeout,
		Concurrency: cfg.Concurrency,
		Retries:     cfg.Retries,
		SrcPort:     randomPort(),
	}

	scanner := portscan.New(scanCfg)
	results, err := scanner.Scan(ip, ports)
	if err != nil {
		return err
	}

	// debug: raw scan results
	if *flagDebug {
		for _, r := range results {
			fmt.Fprintf(os.Stderr, "[debug] scan result: port=%d state=%s\n", r.Port, r.State)
		}
	}

	// banner grabber
	grabber := banner.New(cfg.Timeout)

	// output results
	var jsonPorts []output.JSONPort
	openCount := 0

	for _, r := range results {
		// filtered and closed ports are shown only with -v
		if r.State != portscan.StateOpen && !*flagVerbose {
			continue
		}

		var svc, ban, cveLink string

		if r.State == portscan.StateOpen {
			openCount++
			if cfg.Banner {
				if b, err := grabber.Grab(ip.String(), r.Port); err == nil {
					svc = b.Service
					if b.Service != "" && b.Version != "" {
						ban = fmt.Sprintf("%s/%s", b.Service, b.Version)
					} else if b.Version != "" {
						ban = b.Version
					} else if b.Raw != "" {
						firstLine := strings.SplitN(strings.TrimSpace(b.Raw), "\n", 2)[0]
						if len(firstLine) > 60 {
							firstLine = firstLine[:60]
						}
						ban = firstLine
					}
					cveLink = b.CVELink
				}
			}
		}

		switch cfg.Output {
		case "human":
			output.PrintPort(r.Port, string(r.State), svc, ban, cveLink)
		default:
			jsonPorts = append(jsonPorts, output.JSONPort{
				Port:    r.Port,
				State:   string(r.State),
				Service: svc,
				Banner:  ban,
				CVELink: cveLink,
			})
		}
	}

	// rdns
	var rdnsHostname string
	if cfg.RDNS {
		if res, err := rdns.Lookup(ip.String()); err == nil && res != nil {
			rdnsHostname = res.Hostname
			if cfg.Output == "human" && !*flagSilent {
				output.PrintRDNS(ip.String(), res.Hostname)
			}
		}
	}

	duration := time.Since(start).Round(time.Millisecond).String()

	// final output
	switch cfg.Output {
	case "json":
		res := output.JSONResult{
			Target: target,
			IP:     ip.String(),
			RDNS:   rdnsHostname,
			Ports:  jsonPorts,
			Meta: output.JSONMeta{
				Scanned:  len(ports),
				Open:     openCount,
				Duration: duration,
			},
		}
		if *flagFile != "" {
			output.WriteJSON(*flagFile, res)
		} else {
			output.PrintJSON(res)
		}

	case "csv":
		if *flagFile != "" {
			output.WriteCSV(*flagFile, jsonPorts, rdnsHostname)
		} else {
			output.PrintCSV(jsonPorts, rdnsHostname)
		}

	default:
		if !*flagSilent {
			output.PrintSummary(output.Summary{
				Scanned:  len(ports),
				Open:     openCount,
				Duration: duration,
				Target:   target,
			})
		}
	}

	// return non-nil to signal no open ports to caller
	if openCount == 0 {
		return fmt.Errorf("no open ports found")
	}

	return nil
}

// ─── helpers ──────────────────────────────────────────────────────────────────

// resolveTarget returns the IP for a given hostname or IP string.
func resolveTarget(target string) (net.IP, error) {
	// return early if already an IP
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}

	// domain → resolve
	addrs, err := net.LookupHost(target)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve %s: %s", target, err)
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no addresses found for %s", target)
	}

	ip := net.ParseIP(addrs[0])
	if ip == nil {
		return nil, fmt.Errorf("invalid address: %s", addrs[0])
	}
	return ip, nil
}

// resolvePorts returns the port list based on --full, -p, or --top flags.
func resolvePorts(cfg config.Config) ([]int, error) {
	// --full
	if *flagFull {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports, nil
	}

	// -p 80,443,8080
	if *flagPorts != "" {
		return parsePorts(*flagPorts)
	}

	// --top N
	return topPorts(cfg.Top), nil
}

// parsePorts parses a comma-separated port list (e.g. "80,443,8080").
func parsePorts(s string) ([]int, error) {
	var ports []int
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return nil, fmt.Errorf("invalid port: %s", p)
		}
		ports = append(ports, n)
	}
	return ports, nil
}

// topPorts returns the n most common ports, extending with sequential ports if needed.
func topPorts(n int) []int {
	top := []int{
		80, 443, 22, 21, 25, 53, 110, 143, 445, 3306,
		3389, 8080, 8443, 8888, 27017, 6379, 5432, 1433,
		23, 111, 135, 139, 161, 389, 636, 993, 995,
		1080, 1723, 2049, 2181, 3000, 4444, 5000, 5001,
		5601, 6000, 6443, 7001, 7777, 8000, 8001, 8008,
		8081, 8082, 8083, 8086, 8088, 8089, 8161, 8888,
		9000, 9090, 9200, 9300, 9443, 9600, 9999, 10000,
	}

	if n >= len(top) {
		// n exceeds preset list — fill sequentially
		existing := make(map[int]bool)
		for _, p := range top {
			existing[p] = true
		}
		for i := 1; len(top) < n && i <= 65535; i++ {
			if !existing[i] {
				top = append(top, i)
			}
		}
	}

	if n < len(top) {
		return top[:n]
	}
	return top
}

// isPermErr reports whether err is a PermissionError.
func isPermErr(err error, target interface{}) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*errors.PermissionError)
	return ok
}

// randomPort returns a random ephemeral port in the range 49152–65535.
func randomPort() int {
	// ephemeral port range: 49152–65535
	return 49152 + rand.Intn(16383)
}

// detectInput determines whether input comes from stdin pipe, -t flag, or a file.
func detectInput() (*input, error) {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return nil, err
	}

	if (stat.Mode() & os.ModeCharDevice) == 0 {
		targets, err := readLines(os.Stdin)
		if err != nil {
			return nil, err
		}
		if len(targets) == 0 {
			return nil, fmt.Errorf("no targets received from stdin")
		}
		return &input{mode: modePipe, targets: targets}, nil
	}

	if *flagTarget == "" {
		return nil, nil
	}

	// treat as CIDR if it contains "/" and is not a .txt file path
	if strings.Contains(*flagTarget, "/") && !strings.HasSuffix(*flagTarget, ".txt") {
		return &input{mode: modeFlag, targets: []string{*flagTarget}}, nil
	}

	if isFile(*flagTarget) {
		f, err := os.Open(*flagTarget)
		if err != nil {
			return nil, fmt.Errorf("cannot open file: %s", *flagTarget)
		}
		defer f.Close()

		targets, err := readLines(f)
		if err != nil {
			return nil, err
		}
		return &input{mode: modeFile, targets: targets}, nil
	}

	return &input{mode: modeFlag, targets: []string{*flagTarget}}, nil
}

// readLines reads non-empty, non-comment lines from f.
func readLines(f *os.File) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines, scanner.Err()
}

// isFile reports whether path points to an existing regular file.
func isFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// expandTargets expands CIDR ranges and returns a flat list of targets.
func expandTargets(targets []string) ([]string, error) {
	var expanded []string
	for _, t := range targets {
		if strings.Contains(t, "/") {
			ips, err := expandCIDR(t)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %s: %s", t, err)
			}
			expanded = append(expanded, ips...)
		} else {
			expanded = append(expanded, t)
		}
	}
	return expanded, nil
}

// expandCIDR returns all usable host IPs within the given CIDR block.
func expandCIDR(cidr string) ([]string, error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); incrementIP(ip) {
		if ip[len(ip)-1] == 0 || ip[len(ip)-1] == 255 {
			continue
		}
		ips = append(ips, ip.String())
	}
	return ips, nil
}

// incrementIP increments an IP address by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
