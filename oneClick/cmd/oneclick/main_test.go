package main

import (
	"path/filepath"
	"testing"
)

func TestWordlistStatus(t *testing.T) {
	cases := []struct {
		name     string
		enabled  bool
		wordlist string
		want     string
	}{
		{"disabled", false, "", "off"},
		{"disabled even with a wordlist set", false, "subs.txt", "off"},
		{"enabled and ready", true, "subs.txt", "on"},
		{"enabled but unavailable", true, "", "requested, but unavailable (see warnings above)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := wordlistStatus(c.enabled, c.wordlist)
			if got != c.want {
				t.Errorf("wordlistStatus(%v, %q) = %q, want %q", c.enabled, c.wordlist, got, c.want)
			}
		})
	}
}

func TestLiveLogsStatus(t *testing.T) {
	cases := []struct {
		name              string
		live, quietStages bool
		want              string
	}{
		{"off, quiet-stages ignored", false, false, "off"},
		{"off even with quiet-stages", false, true, "off"},
		{"live, full raw stream", true, false, "on"},
		{"live, quieted to banners/summaries only", true, true, "on (stage banners/summaries only, see quiet-stages)"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := liveLogsStatus(c.live, c.quietStages)
			if got != c.want {
				t.Errorf("liveLogsStatus(%v, %v) = %q, want %q", c.live, c.quietStages, got, c.want)
			}
		})
	}
}

func TestOnOff(t *testing.T) {
	if got := onOff(true); got != "on" {
		t.Errorf("onOff(true) = %q, want \"on\"", got)
	}
	if got := onOff(false); got != "off" {
		t.Errorf("onOff(false) = %q, want \"off\"", got)
	}
}

func TestSanitizeName(t *testing.T) {
	cases := map[string]string{
		"example.com":        "example.com",
		"":                   "",
		"a b/c:d":            "a_b_c_d",
		"http://example.com": "http___example.com",
	}
	for in, want := range cases {
		if got := sanitizeName(in); got != want {
			t.Errorf("sanitizeName(%q) = %q, want %q", in, got, want)
		}
	}

	long := ""
	for i := 0; i < 100; i++ {
		long += "a"
	}
	if got := sanitizeName(long); len(got) != 60 {
		t.Errorf("sanitizeName should truncate to 60 chars, got length %d", len(got))
	}
}

func TestMergeSanitizedHosts(t *testing.T) {
	dir := t.TempDir()
	inputPath := filepath.Join(dir, "input.txt")
	subsPath := filepath.Join(dir, "subs.txt")

	if err := writeLines(inputPath, []string{"example.com"}); err != nil {
		t.Fatal(err)
	}
	// Simulates what a flaky/blocked source can inject into SubEnum's
	// output: an error message on its own line, blank lines, and a
	// legitimate discovered subdomain.
	if err := writeLines(subsPath, []string{
		"www.example.com",
		"Host not in allowlist: api.hackertarget.com. Add this host to your network egress settings to allow access.",
		"",
		"api.example.com",
	}); err != nil {
		t.Fatal(err)
	}

	if err := mergeSanitizedHosts(inputPath, subsPath); err != nil {
		t.Fatalf("mergeSanitizedHosts: %v", err)
	}

	got, err := readLines(subsPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.example.com", "example.com", "www.example.com"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
		}
	}
}

func TestFilterJSURLs(t *testing.T) {
	dir := t.TempDir()
	urlsPath := filepath.Join(dir, "urls.txt")
	jsPath := filepath.Join(dir, "js.txt")

	if err := writeLines(urlsPath, []string{
		"https://example.com/app.js",
		"https://example.com/app.js?v=123",
		"https://example.com/app.js.map",
		"https://example.com/data.json.js",
		"https://example.com/style.css",
		"https://example.com/App.JS",
		"",
	}); err != nil {
		t.Fatal(err)
	}

	if err := filterJSURLs(urlsPath, jsPath); err != nil {
		t.Fatalf("filterJSURLs: %v", err)
	}

	got, err := readLines(jsPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"https://example.com/App.JS", "https://example.com/app.js", "https://example.com/app.js?v=123"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("got[%d] = %q, want %q (full: got=%v want=%v)", i, got[i], want[i], got, want)
		}
	}
}

func TestCountNonEmptyLines(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "f.txt")
	if err := writeLines(path, []string{"a", "", "b", "  ", "c"}); err != nil {
		t.Fatal(err)
	}
	if got := countNonEmptyLines(path); got != 3 {
		t.Errorf("countNonEmptyLines = %d, want 3", got)
	}
	if got := countNonEmptyLines(filepath.Join(dir, "does-not-exist.txt")); got != 0 {
		t.Errorf("countNonEmptyLines of missing file = %d, want 0", got)
	}
}
