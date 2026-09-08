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

// runPortScan TCP-connect scans every discovered subdomain (subsPath) with
// the portScanner tool, writing every open host:port pair to portsPath
// and, separately, only the "notable" ones -- open ports other than 80
// and 443, the two expected open on any web target -- to
// portScanningPath.
//
// Returns the portScanner subprocess exit code (0 on success and when
// there's nothing to scan), the total number of open ports found, and the
// number of those that are notable (not 80/443).
func runPortScan(repoRoot, subsPath, portsPath, portScanningPath, portsSpec string, allPorts bool, concurrency, timeout int, logFile io.Writer, live bool) (int, int, int) {
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

	args := []string{
		"-host-file", subsPath,
		"-output-file", portsPath,
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

	lines, err := readLines(portsPath)
	if err != nil {
		if !os.IsNotExist(err) {
			warn("Could not read port scan results: %v", err)
		}
		return rc, 0, 0
	}

	total, notable := filterNotablePorts(lines)
	if err := writeLines(portScanningPath, notable); err != nil {
		warn("Could not write %s: %v", portScanningPath, err)
		return rc, total, 0
	}
	return rc, total, len(notable)
}

// filterNotablePorts counts the open host:port results in lines (as
// written by portScanner's -output-file) and picks out the "notable"
// ones -- open ports other than 80 and 443, the two expected open on any
// web target. Blank lines and anything that doesn't parse as host:port
// are skipped.
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
		if port != 80 && port != 443 {
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
