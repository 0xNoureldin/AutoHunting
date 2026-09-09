package main

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// portScanTimeoutSeconds caps the per-port connection timeout passed to
// portScanner, decoupled from the general pipeline -timeout (which
// -active/-fuzz-subs/-fuzz-urls/-vhost can bump to 300s as a per-target
// *budget*). portScanner's -timeout is the dial timeout for a single TCP
// connect attempt, not a budget, so inheriting 300s there would make
// every closed/filtered port take up to five minutes to time out instead
// of a few seconds.
const portScanTimeoutSeconds = 5

// portScanThreadsFloor is the minimum port concurrency (per host) used for
// port scanning, regardless of the general pipeline -concurrency. A TCP
// connect probe is as cheap as a DNS query, so scanning even the default
// 100-port list one at a time per host would be far slower than needed.
const portScanThreadsFloor = 50

// ignoredPorts are the common web ports excluded from ports.txt: 80/443
// are already covered by every other web-facing stage here, and 8080/8443
// are common enough alternates that seeing them open on every host is
// noise rather than signal. Anything else found open is kept.
var ignoredPorts = map[int]struct{}{
	80:   {},
	443:  {},
	8080: {},
	8443: {},
}

// runPortScan TCP-connect scans every discovered subdomain (subsPath)
// with the portScanner tool. Only "notable" open ports (see ignoredPorts)
// are kept: written to portsPath, and -- as "host:port" -- merged into
// subsPath too, so URL enumeration also targets that specific port
// directly instead of only the default web ports.
//
// Returns the portScanner subprocess exit code (0 on success and when
// there's nothing to scan), the total number of open ports found (before
// filtering), and the number of those that are notable and kept.
func runPortScan(repoRoot, subsPath, portsPath, portsSpec string, allPorts bool, concurrency, timeout int, logFile io.Writer, live bool) (int, int, int) {
	if countNonEmptyLines(subsPath) == 0 {
		warn("No subdomains to port-scan, skipping")
		return 0, 0, 0
	}

	scanTimeout := timeout
	if scanTimeout > portScanTimeoutSeconds {
		scanTimeout = portScanTimeoutSeconds
	}
	portThreads := concurrency
	if portThreads < portScanThreadsFloor {
		portThreads = portScanThreadsFloor
	}

	// portScanner has no notion of "notable" ports -- it just reports
	// everything open -- so it writes to a scratch file that's cleaned up
	// once filterNotablePorts has picked out what's worth keeping.
	rawPortsPath := portsPath + ".raw"
	defer os.Remove(rawPortsPath)

	args := []string{
		"-host-file", subsPath,
		"-output-file", rawPortsPath,
		"-timeout", strconv.Itoa(scanTimeout),
		"-host-threads", strconv.Itoa(concurrency),
		"-threads", strconv.Itoa(portThreads),
	}
	switch {
	case portsSpec != "":
		// A specific -ports spec always wins, matching portScanner's own
		// precedence.
		args = append(args, "-ports", portsSpec)
	case allPorts:
		args = append(args, "-all-ports")
	}

	rc := runGoTool(filepath.Join(repoRoot, "portScanner"), args, logFile, live)

	lines, err := readLines(rawPortsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			warn("Could not read port scan results: %v", err)
		}
		return rc, 0, 0
	}

	total, notable := filterNotablePorts(lines)
	if err := writeLines(portsPath, notable); err != nil {
		warn("Could not write %s: %v", portsPath, err)
		return rc, total, 0
	}
	if len(notable) > 0 {
		if err := mergeSanitizedHosts(portsPath, subsPath); err != nil {
			warn("Could not merge notable-port hosts into %s: %v", subsPath, err)
		}
	}
	return rc, total, len(notable)
}

// filterNotablePorts counts the open host:port results in lines (as
// written by portScanner's -output-file) and picks out the "notable"
// ones -- see ignoredPorts. Blank lines and anything that doesn't parse
// as host:port are skipped.
func filterNotablePorts(lines []string) (total int, notable []string) {
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		total++
		idx := strings.LastIndex(l, ":")
		if idx < 0 {
			continue
		}
		port, err := strconv.Atoi(l[idx+1:])
		if err != nil {
			continue
		}
		if _, ignored := ignoredPorts[port]; !ignored {
			notable = append(notable, l)
		}
	}
	return total, notable
}

// portScanStatus describes the port-scanning stage for the banner and
// summary: off, on with a specific -ports spec, on scanning all 65535
// ports, or on with the default top-100 list.
func portScanStatus(enabled, allPorts bool, portsSpec string) string {
	switch {
	case !enabled:
		return "off"
	case portsSpec != "":
		return "on (ports: " + portsSpec + ")"
	case allPorts:
		return "on (all 65535 ports)"
	default:
		return "on (top 100 ports)"
	}
}
