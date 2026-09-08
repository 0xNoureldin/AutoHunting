package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Default wordlists are SecLists' most widely used general-purpose lists
// for each technique: a solid balance of coverage vs. run time for a
// "one click" tool, rather than the largest lists available.
const (
	defaultSubdomainWordlistURL = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt"
	defaultPathWordlistURL      = "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"
)

// ensureWordlist returns a local path to the wordlist normally fetched from
// url, downloading and caching it under cacheDir on first use. An
// already-cached, non-empty file is reused as-is without re-downloading.
func ensureWordlist(cacheDir, filename, url string) (string, error) {
	path := filepath.Join(cacheDir, filename)

	if info, err := os.Stat(path); err == nil && info.Size() > 0 {
		return path, nil
	}

	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return "", fmt.Errorf("create wordlist cache dir: %w", err)
	}

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download %s: unexpected status %s", url, resp.Status)
	}

	// Download to a temp file first and rename into place, so a failed or
	// interrupted download never leaves a corrupt/partial file cached.
	tmp, err := os.CreateTemp(cacheDir, ".wordlist-*.tmp")
	if err != nil {
		return "", fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath) // no-op once successfully renamed below

	n, copyErr := io.Copy(tmp, resp.Body)
	closeErr := tmp.Close()
	if copyErr != nil {
		return "", fmt.Errorf("download %s: %w", url, copyErr)
	}
	if closeErr != nil {
		return "", fmt.Errorf("write wordlist: %w", closeErr)
	}
	if n == 0 {
		return "", fmt.Errorf("download %s: empty response", url)
	}

	if err := os.Rename(tmpPath, path); err != nil {
		return "", fmt.Errorf("save wordlist: %w", err)
	}
	return path, nil
}
