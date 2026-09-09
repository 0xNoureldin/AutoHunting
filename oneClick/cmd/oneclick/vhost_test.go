package main

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
)

func TestReadVhosterResults(t *testing.T) {
	dir := t.TempDir()

	t.Run("flattens and dedupes across targets", func(t *testing.T) {
		path := filepath.Join(dir, "results.json")
		if err := os.WriteFile(path, []byte(`{
			"example.com": ["admin.example.com", "www.example.com"],
			"other.example.com": ["admin.example.com", "staging.example.com"]
		}`), 0o644); err != nil {
			t.Fatal(err)
		}

		got, err := readVhosterResults(path)
		if err != nil {
			t.Fatalf("readVhosterResults: %v", err)
		}
		sort.Strings(got)
		want := []string{"admin.example.com", "staging.example.com", "www.example.com"}
		if len(got) != len(want) {
			t.Fatalf("got %v, want %v", got, want)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Errorf("got[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
			}
		}
	})

	t.Run("empty results object", func(t *testing.T) {
		path := filepath.Join(dir, "empty.json")
		if err := os.WriteFile(path, []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		got, err := readVhosterResults(path)
		if err != nil {
			t.Fatalf("readVhosterResults: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected no results, got %v", got)
		}
	})

	t.Run("missing file is not an error", func(t *testing.T) {
		got, err := readVhosterResults(filepath.Join(dir, "does-not-exist.json"))
		if err != nil {
			t.Fatalf("readVhosterResults on a missing file should not error, got: %v", err)
		}
		if len(got) != 0 {
			t.Errorf("expected no results, got %v", got)
		}
	})
}

func TestRunVhostFuzzSkipsWithoutWordlist(t *testing.T) {
	dir := t.TempDir()
	subsPath := filepath.Join(dir, "subdomains.txt")
	if err := writeLines(subsPath, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}

	logFile, err := os.Create(filepath.Join(dir, "log.txt"))
	if err != nil {
		t.Fatal(err)
	}
	defer logFile.Close()

	vhostSubsPath := filepath.Join(dir, "vhost_subdomains.txt")
	vhostForbiddenPath := filepath.Join(dir, "vhost_403.txt")
	rc, count, forbiddenCount := runVhostFuzz("/repo/root", []string{"example.com"}, "", subsPath, vhostSubsPath, vhostForbiddenPath, 10, 60, logFile, false)
	if rc != 0 {
		t.Errorf("runVhostFuzz with no wordlist should return 0 (nothing to do), got %d", rc)
	}
	if count != 0 {
		t.Errorf("runVhostFuzz with no wordlist should discover 0 vhosts, got %d", count)
	}
	if forbiddenCount != 0 {
		t.Errorf("runVhostFuzz with no wordlist should record 0 403s, got %d", forbiddenCount)
	}

	got, err := readLines(subsPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "example.com" {
		t.Errorf("subdomains.txt should be untouched when there's no wordlist, got %v", got)
	}
}
