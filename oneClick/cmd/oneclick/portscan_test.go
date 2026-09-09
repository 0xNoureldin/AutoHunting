package main

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestFilterNotablePorts(t *testing.T) {
	lines := []string{
		"admin.example.com:80",
		"admin.example.com:443",
		"admin.example.com:8080",
		"admin.example.com:8443",
		"",
		"  ",
		"api.example.com:443",
		"api.example.com:22",
		"garbage-no-port",
		"weird:host:9200",
	}

	total, notable := filterNotablePorts(lines)

	if total != 8 {
		t.Fatalf("total = %d, want 8 (blank lines excluded)", total)
	}

	want := []string{
		"api.example.com:22",
		"weird:host:9200",
	}
	if len(notable) != len(want) {
		t.Fatalf("notable = %v, want %v", notable, want)
	}
	for i := range want {
		if notable[i] != want[i] {
			t.Errorf("notable[%d] = %q, want %q (full: got=%v want=%v)", i, notable[i], want[i], notable, want)
		}
	}
}

func TestFilterNotablePortsAllStandard(t *testing.T) {
	lines := []string{
		"a.example.com:80",
		"b.example.com:443",
		"c.example.com:8080",
		"d.example.com:8443",
	}
	total, notable := filterNotablePorts(lines)
	if total != 4 {
		t.Fatalf("total = %d, want 4", total)
	}
	if len(notable) != 0 {
		t.Errorf("expected no notable ports (80/443/8080/8443 all ignored), got %v", notable)
	}
}

func TestFilterNotablePortsEmpty(t *testing.T) {
	total, notable := filterNotablePorts(nil)
	if total != 0 || len(notable) != 0 {
		t.Errorf("expected (0, nil), got (%d, %v)", total, notable)
	}
}

func TestRunPortScanSkipsWithoutSubdomains(t *testing.T) {
	dir := t.TempDir()
	subsPath := filepath.Join(dir, "subdomains.txt")
	if err := writeLines(subsPath, nil); err != nil {
		t.Fatal(err)
	}

	logFile, err := os.Create(filepath.Join(dir, "log.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	portsPath := filepath.Join(dir, "ports.txt")
	rc, total, notable := runPortScan("/repo/root", subsPath, portsPath, "", false, 10, 60, logFile, false)
	if rc != 0 {
		t.Errorf("runPortScan with no subdomains should return rc 0 (nothing to do), got %d", rc)
	}
	if total != 0 || notable != 0 {
		t.Errorf("runPortScan with no subdomains should find nothing, got total=%d notable=%d", total, notable)
	}
	if _, err := os.Stat(portsPath); !os.IsNotExist(err) {
		t.Errorf("ports.txt should not be created when there's nothing to scan")
	}
}

// TestRunPortScanMergesNotablePortIntoSubdomains is a regression test for
// the requested behavior: a notable open port (not 80/443/8080/8443)
// must end up in ports.txt as host:port AND get merged into
// subdomains.txt the same way, so URL enumeration targets that specific
// port directly -- while an ignored port (80, tested here) must not.
func TestRunPortScanMergesNotablePortIntoSubdomains(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to bind a test listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	_, portStr, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("could not parse listener address %q: %v", ln.Addr().String(), err)
	}
	notablePort, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("could not parse port %q: %v", portStr, err)
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		t.Fatalf("findRepoRoot: %v", err)
	}
	dir := t.TempDir()
	subsPath := filepath.Join(dir, "subdomains.txt")
	if err := writeLines(subsPath, []string{"127.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	logFile, err := os.Create(filepath.Join(dir, "log.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	portsPath := filepath.Join(dir, "ports.txt")
	portsSpec := "80," + portStr
	rc, total, notable := runPortScan(repoRoot, subsPath, portsPath, portsSpec, false, 5, 3, logFile, false)
	if rc != 0 {
		t.Fatalf("runPortScan failed (rc=%d), check %s", rc, logFile.Name())
	}
	if total != 1 {
		t.Fatalf("expected 1 total open port (only the notable one -- port 80 isn't listening here), got %d", total)
	}
	if notable != 1 {
		t.Fatalf("expected 1 notable open port, got %d", notable)
	}

	gotPorts, err := readLines(portsPath)
	if err != nil {
		t.Fatalf("reading ports.txt: %v", err)
	}
	wantPortsLine := "127.0.0.1:" + portStr
	if len(gotPorts) != 1 || gotPorts[0] != wantPortsLine {
		t.Errorf("ports.txt = %v, want [%q]", gotPorts, wantPortsLine)
	}

	gotSubs, err := readLines(subsPath)
	if err != nil {
		t.Fatalf("reading subdomains.txt: %v", err)
	}
	foundMerged := false
	for _, s := range gotSubs {
		if s == wantPortsLine {
			foundMerged = true
		}
		if s == "127.0.0.1:80" {
			t.Errorf("ignored port 80 must not be merged into subdomains.txt, got %v", gotSubs)
		}
	}
	if !foundMerged {
		t.Errorf("expected %q merged into subdomains.txt, got %v", wantPortsLine, gotSubs)
	}
	// The original seed host must still be there too, deduped (not
	// duplicated by the merge).
	seen := map[string]int{}
	for _, s := range gotSubs {
		seen[s]++
	}
	for host, n := range seen {
		if n > 1 {
			t.Errorf("duplicate entry %q appears %d times in subdomains.txt: %v", host, n, gotSubs)
		}
	}
	if seen["127.0.0.1"] != 1 {
		t.Errorf("expected the original seed host 127.0.0.1 to still be present exactly once, got %v", gotSubs)
	}
	if notablePort == 0 {
		t.Fatal("test setup error: notablePort should never be 0")
	}
}

func TestPortScanStatus(t *testing.T) {
	cases := []struct {
		enabled, allPorts bool
		portsSpec         string
		want              string
	}{
		{false, false, "", "off"},
		{false, true, "1-100", "off"},
		{true, false, "", "on (top 100 ports)"},
		{true, true, "", "on (all 65535 ports)"},
		{true, false, "80,443,8080", "on (ports: 80,443,8080)"},
		{true, true, "80,443,8080", "on (ports: 80,443,8080)"},
	}
	for _, c := range cases {
		got := portScanStatus(c.enabled, c.allPorts, c.portsSpec)
		if got != c.want {
			t.Errorf("portScanStatus(%v, %v, %q) = %q, want %q", c.enabled, c.allPorts, c.portsSpec, got, c.want)
		}
	}
}
