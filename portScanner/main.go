package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

var Top100Ports = []int{
	80, 443, 22, 21, 25, 53, 110, 139, 445, 143,
	3306, 3389, 5900, 8080, 8443, 1433, 6379, 1521, 5432, 9200,
	27017, 5000, 8000, 9000, 23, 389, 636, 2049, 111, 995,
	993, 587, 1025, 1026, 1027, 1028, 1029, 10443,
	49152, 49153, 49154, 49155, 49156, 49157, 49158, 49159,
	49160, 49161, 49162, 49163, 49164, 49165, 49166, 49167,
	49168, 49169, 49170, 49171, 49172, 49173, 49174, 49175,
	49176, 49177, 49178, 49179, 49180, 49181, 49182, 49183,
	49184, 49185, 49186, 49187, 49188, 49189, 49190, 49191,
	49192, 49193, 49194, 49195, 49196, 49197, 49198, 49199,
}

func scanPort(connType, host string, port int, timeout time.Duration) bool {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := net.DialTimeout(connType, addr, timeout)
	if err != nil {
		return false
	}
	defer conn.Close()
	return true
}

// parsePorts supports: "80,443,1000-2000"
func parsePorts(s string) ([]int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, fmt.Errorf("empty ports string")
	}

	set := make(map[int]struct{})
	parts := strings.Split(s, ",")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}

		// Range like 1000-2000
		if strings.Contains(part, "-") {
			ends := strings.SplitN(part, "-", 2)
			if len(ends) != 2 {
				return nil, fmt.Errorf("invalid range: %q", part)
			}
			start, err := strconv.Atoi(strings.TrimSpace(ends[0]))
			if err != nil {
				return nil, fmt.Errorf("invalid range start %q: %w", ends[0], err)
			}
			end, err := strconv.Atoi(strings.TrimSpace(ends[1]))
			if err != nil {
				return nil, fmt.Errorf("invalid range end %q: %w", ends[1], err)
			}
			if start < 1 || end > 65535 || start > end {
				return nil, fmt.Errorf("invalid port range: %d-%d", start, end)
			}
			for p := start; p <= end; p++ {
				set[p] = struct{}{}
			}
			continue
		}

		// Single port like 80
		p, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("invalid port %q: %w", part, err)
		}
		if p < 1 || p > 65535 {
			return nil, fmt.Errorf("port out of range: %d", p)
		}
		set[p] = struct{}{}
	}

	out := make([]int, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Ints(out)
	return out, nil
}

func readHostsFromFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var hosts []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts = append(hosts, line)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

func main() {
	start := time.Now()

	host := flag.String("host", "", "Target host to scan")
	portsFlag := flag.String("ports", "", "Comma-separated list of ports or port ranges to scan (e.g., 80,443,1000-2000)")
	allPorts := flag.Bool("all-ports", false, "Scan all 65535 ports instead of the default top 100 (ignored if -ports is set)")
	timeout := flag.Int("timeout", 10, "Timeout in seconds for each port scan")
	portThreads := flag.Int("threads", 10, "Number of concurrent threads to use for port scanning")
	hostThreads := flag.Int("host-threads", 10, "Number of concurrent threads to use for host scanning")
	hostFile := flag.String("host-file", "", "File containing list of hosts to scan (one per line)")
	connectionType := flag.String("connection-type", "tcp", "Type of connection to use (tcp/udp)")
	outputFile := flag.String("output-file", "", "File to write the scan results to")
	flag.Parse()

	if *timeout < 1 {
		log.Fatal("timeout must be at least 1 second")
	}
	if *portThreads < 1 {
		log.Fatal("threads must be at least 1")
	}
	if *hostThreads < 1 {
		log.Fatal("host-threads must be at least 1")
	}

	connType := strings.ToLower(strings.TrimSpace(*connectionType))
	if connType != "tcp" && connType != "udp" {
		log.Fatal("connection-type must be tcp or udp")
	}

	// Decide which hosts to scan
	var hosts []string
	if strings.TrimSpace(*hostFile) != "" {
		h, err := readHostsFromFile(*hostFile)
		if err != nil {
			log.Fatalf("failed to read host-file: %v", err)
		}
		hosts = h
	} else {
		if strings.TrimSpace(*host) == "" {
			log.Fatal("Host is required (use -host or -host-file)")
		}
		hosts = []string{strings.TrimSpace(*host)}
	}

	if len(hosts) == 0 {
		log.Fatal("no hosts to scan")
	}

	// Decide which ports to scan: -ports takes precedence, then -all-ports,
	// falling back to the default top-100 list.
	portsToScan := Top100Ports
	if strings.TrimSpace(*portsFlag) != "" {
		parsed, err := parsePorts(*portsFlag)
		if err != nil {
			log.Fatalf("invalid -ports value: %v", err)
		}
		portsToScan = parsed
	} else if *allPorts {
		portsToScan = make([]int, 65535)
		for i := range portsToScan {
			portsToScan[i] = i + 1
		}
	}

	fmt.Printf("Scanning %d host(s) | %d port(s) | conn=%s | timeout=%ds | hostThreads=%d | portThreads=%d\n",
		len(hosts), len(portsToScan), connType, *timeout, *hostThreads, *portThreads)

	// Collect results for output
	// map[host][]openPorts
	results := make(map[string][]int)
	var resultsMu sync.Mutex

	// host concurrency control
	hostSem := make(chan struct{}, *hostThreads)
	var hostsWg sync.WaitGroup

	for _, h := range hosts {
		h := h
		hostsWg.Add(1)

		go func() {
			defer hostsWg.Done()
			hostSem <- struct{}{}
			defer func() { <-hostSem }()

			// port concurrency control (per host)
			portSem := make(chan struct{}, *portThreads)
			var portsWg sync.WaitGroup

			for _, port := range portsToScan {
				port := port
				portsWg.Add(1)

				go func() {
					defer portsWg.Done()
					portSem <- struct{}{}
					defer func() { <-portSem }()

					if scanPort(connType, h, port, time.Duration(*timeout)*time.Second) {
						// UDP note: DialTimeout success often means "open|filtered"
						fmt.Printf("%s:%d OPEN\n", h, port)

						resultsMu.Lock()
						results[h] = append(results[h], port)
						resultsMu.Unlock()
					}
				}()
			}

			portsWg.Wait()

			// Keep ports sorted per host
			resultsMu.Lock()
			sort.Ints(results[h])
			resultsMu.Unlock()
		}()
	}

	hostsWg.Wait()

	// Write output if requested
	if strings.TrimSpace(*outputFile) != "" {
		f, err := os.Create(*outputFile)
		if err != nil {
			log.Fatalf("failed to create output file: %v", err)
		}
		defer f.Close()

		// simple, readable output
		hostsSorted := make([]string, 0, len(results))
		for h := range results {
			hostsSorted = append(hostsSorted, h)
		}
		sort.Strings(hostsSorted)

		for _, h := range hostsSorted {
			for _, p := range results[h] {
				_, _ = fmt.Fprintf(f, "%s:%d\n", h, p)
			}
		}

		fmt.Printf("Results written to %s\n", *outputFile)
	}

	fmt.Printf("Done in %s\n", time.Since(start).Round(time.Millisecond))
}
