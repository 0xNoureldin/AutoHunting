package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFilterNotablePorts(t *testing.T) {
	lines := []string{
		"admin.example.com:80",
		"admin.example.com:443",
		"admin.example.com:8080",
		"",
		"  ",
		"api.example.com:443",
		"api.example.com:22",
		"garbage-no-port",
		"weird:host:9200",
	}

	total, notable := filterNotablePorts(lines)

	if total != 7 {
		t.Fatalf("total = %d, want 7 (blank lines excluded)", total)
	}

	want := []string{
		"admin.example.com:8080",
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
	lines := []string{"a.example.com:80", "b.example.com:443"}
	total, notable := filterNotablePorts(lines)
	if total != 2 {
		t.Fatalf("total = %d, want 2", total)
	}
	if len(notable) != 0 {
		t.Errorf("expected no notable ports, got %v", notable)
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
	portScanningPath := filepath.Join(dir, "portScanning.txt")
	rc, total, notable := runPortScan("/repo/root", subsPath, portsPath, portScanningPath, "", false, 10, 60, logFile, false)
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
