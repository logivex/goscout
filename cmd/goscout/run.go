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
	"github.com/logivex/goscout/internal/httpprobe"
	"github.com/logivex/goscout/internal/output"
	"github.com/logivex/goscout/internal/portscan"
	"github.com/logivex/goscout/internal/rdns"
)

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

	ports, err := resolvePorts(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %s\n", err)
		os.Exit(2)
	}

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
			err := scanTarget(t, ports, cfg, &printMu)
			if err != nil {
				var permErr *errors.PermissionError
				if isPermErr(err, permErr) {
					fmt.Fprintf(os.Stderr, "%s\n", err)
					os.Exit(3)
				}
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

// scanTarget resolves, scans, and prints results for a single target.
func scanTarget(target string, ports []int, cfg config.Config, mu *sync.Mutex) error {
	ip, err := resolveTarget(target)
	if err != nil {
		return err
	}

	if !*flagSilent && cfg.Output == "human" {
		mu.Lock()
		output.PrintHeader(target, ip.String(), version)
		mu.Unlock()
	}

	start := time.Now()

	// reduce concurrency for large scans to avoid network buffer overflow
	concurrency := cfg.Concurrency
	if len(ports) > 10000 && concurrency > 200 {
		concurrency = 200
	}

	scanCfg := portscan.Config{
		Rate:        cfg.Rate,
		Timeout:     cfg.Timeout,
		Concurrency: concurrency,
		Retries:     cfg.Retries,
		SrcPort:     randomPort(),
	}

	scanner := portscan.New(scanCfg)
	results, err := scanner.Scan(ip, ports)
	if err != nil {
		return err
	}

	if *flagDebug {
		for _, r := range results {
			fmt.Fprintf(os.Stderr, "[debug] scan result: port=%d state=%s\n", r.Port, r.State)
		}
	}

	grabber := banner.New(cfg.Timeout)
	prober := httpprobe.New(5 * time.Second)

	type portRow struct {
		port    int
		state   string
		svc     string
		ban     string
		tech    []string
		cveLink string
	}

	var rows []portRow
	var jsonPorts []output.JSONPort
	openCount := 0

	for _, r := range results {
		if r.State != portscan.StateOpen && !*flagVerbose {
			continue
		}

		var svc, ban, cveLink string
		var tech []string

		if r.State == portscan.StateOpen {
			openCount++

			isHTTPPort := r.Port == 80 || r.Port == 443 || r.Port == 8080 || r.Port == 8443 || r.Port == 8888

			if cfg.Banner && !(isHTTPPort && *flagHTTP) {
				if b, err := grabber.Grab(target, r.Port); err == nil {
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

			if *flagHTTP {
				if h, err := prober.Probe(target, r.Port); err == nil {
					httpInfo := fmt.Sprintf("[%d]", h.StatusCode)
					if h.Title != "" {
						httpInfo += fmt.Sprintf(" %q", h.Title)
					}
					if h.Redirect != "" {
						httpInfo += fmt.Sprintf(" → %s", h.Redirect)
					}
					if len(h.Tech) > 0 {
						httpInfo += fmt.Sprintf(" (%s)", strings.Join(h.Tech, ", "))
					}
					if ban != "" {
						ban = ban + "  " + httpInfo
					} else {
						ban = httpInfo
					}
					tech = h.Tech
				} else if *flagDebug {
					fmt.Fprintf(os.Stderr, "[debug] http probe %s:%d failed: %s\n", target, r.Port, err)
				}
			}
		}

		rows = append(rows, portRow{r.Port, string(r.State), svc, ban, tech, cveLink})
		if cfg.Output != "human" {
			jsonPorts = append(jsonPorts, output.JSONPort{
				Port:    r.Port,
				State:   string(r.State),
				Service: svc,
				Banner:  ban,
				Tech:    tech,
				CVELink: cveLink,
			})
		}
	}

	var rdnsHostname string
	if cfg.RDNS {
		if res, err := rdns.Lookup(ip.String()); err == nil && res != nil {
			rdnsHostname = res.Hostname
		}
	}

	duration := time.Since(start).Round(time.Millisecond).String()

	mu.Lock()
	defer mu.Unlock()

	if cfg.Output == "human" {
		for _, row := range rows {
			output.PrintPort(row.port, row.state, row.svc, row.ban, row.cveLink)
		}
		if rdnsHostname != "" && !*flagSilent {
			output.PrintRDNS(ip.String(), rdnsHostname)
		}
	}

	switch cfg.Output {
	case "json":
		res := output.NewJSONResult(
			target,
			ip.String(),
			rdnsHostname,
			jsonPorts,
			output.JSONMeta{
				Scanned:  len(ports),
				Open:     openCount,
				Duration: duration,
			},
		)
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

	if openCount == 0 {
		return fmt.Errorf("no open ports found")
	}

	return nil
}

// resolveTarget returns the IP address for a hostname or IP string.
func resolveTarget(target string) (net.IP, error) {
	if ip := net.ParseIP(target); ip != nil {
		return ip, nil
	}

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

// resolvePorts returns the list of ports to scan based on active flags.
func resolvePorts(cfg config.Config) ([]int, error) {
	if *flagFull {
		ports := make([]int, 65535)
		for i := range ports {
			ports[i] = i + 1
		}
		return ports, nil
	}

	if *flagPorts != "" {
		return parsePorts(*flagPorts)
	}

	return topPorts(cfg.Top), nil
}

// parsePorts parses a comma-separated list of ports or ranges (e.g. "80,443,8000-8100").
func parsePorts(s string) ([]int, error) {
	var ports []int
	seen := make(map[int]bool)

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)

		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			if len(bounds) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			start, err1 := strconv.Atoi(strings.TrimSpace(bounds[0]))
			end, err2 := strconv.Atoi(strings.TrimSpace(bounds[1]))
			if err1 != nil || err2 != nil || start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %s", part)
			}
			for i := start; i <= end; i++ {
				if !seen[i] {
					seen[i] = true
					ports = append(ports, i)
				}
			}
		} else {
			n, err := strconv.Atoi(part)
			if err != nil || n < 1 || n > 65535 {
				return nil, fmt.Errorf("invalid port: %s", part)
			}
			if !seen[n] {
				seen[n] = true
				ports = append(ports, n)
			}
		}
	}
	return ports, nil
}

// topPorts returns the n most commonly scanned ports.
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

// randomPort returns a random port in the ephemeral range 49152–65535.
func randomPort() int {
	return 49152 + rand.Intn(16383)
}

// detectInput determines the input source: pipe, -t flag, or file.
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

// readLines reads non-empty, non-comment lines from r.
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

// isFile reports whether path is an existing regular file.
func isFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil {
		return false
	}
	return !info.IsDir()
}

// expandTargets expands any CIDR ranges into individual IP addresses.
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

// expandCIDR returns all usable host addresses within a CIDR block.
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

// incrementIP increments an IP address in-place by one.
func incrementIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}
