package main

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// vhostRequestTimeoutSeconds caps the per-HTTP-request timeout passed to
// the vhoster tool, decoupled from the general pipeline -timeout (which
// -active/-fuzz-subs/-fuzz-urls/-vhost itself can bump to 300s as a
// per-target *budget*). vhoster's -timeout is a per-request timeout, not a
// budget, so inheriting 300s there would let one hanging request block a
// worker for five minutes instead of a few seconds.
const vhostRequestTimeoutSeconds = 15

// vhostConcurrencyCap keeps vhost fuzzing from hammering the single server
// it's repeatedly hitting. Unlike DNS brute-force (spread across several
// public resolvers) or path fuzzing (many paths, but still one connection
// target), every vhost request goes to the exact same host, so high
// concurrency risks overwhelming or getting rate-limited/blocked by the
// very target being scanned.
const vhostConcurrencyCap = 10

// runVhostFuzz discovers virtual hosts that don't have their own DNS
// record: it builds "word.domain" candidates from wordlist for every
// domain in domains, runs the vhosts/cmd/vhoster tool (Host-header fuzzing
// against each domain's own resolved connection target, baseline-diffed
// so only genuinely distinct responses are reported), writes whatever it
// finds to vhostSubsPath (sanitized, deduped, sorted -- a standalone
// deliverable in its own right, not just an intermediate file), and also
// merges those same hosts into subsPath alongside the existing subdomain
// list, so later stages see them too.
//
// Separately, every candidate whose response came back 403 Forbidden --
// regardless of whether it was confirmed as a distinct vhost -- is
// sanitized and written to forbiddenPath. A 403 usually means the host
// exists and is being actively gated (an internal admin panel, an
// IP-allowlisted endpoint), which is worth a human's attention even when
// vhoster's own baseline-diffing doesn't consider it different enough to
// count as a hit (many WAFs/default vhosts return the same generic 403
// page for every unrecognized Host too). These are NOT merged into
// subsPath: unlike a confirmed vhost, a 403 alone isn't strong enough
// evidence of a genuinely distinct host to feed into later stages, so
// they're left for manual follow-up instead.
//
// Returns the vhoster subprocess exit code (0 on success and when there's
// nothing to do, e.g. no wordlist available), the number of distinct
// vhosts discovered, and the number of 403 responses recorded.
func runVhostFuzz(repoRoot string, domains []string, wordlist, subsPath, vhostSubsPath, forbiddenPath string, concurrency, timeout int, logFile io.Writer, live bool) (int, int, int) {
	if wordlist == "" {
		warn("No subdomain wordlist available, skipping vhost discovery")
		return 0, 0, 0
	}

	words, err := readLines(wordlist)
	if err != nil {
		warn("Could not read wordlist for vhost discovery: %v", err)
		return 0, 0, 0
	}

	outDir := filepath.Dir(subsPath)
	hostsPath := filepath.Join(outDir, "vhost_candidates.txt")
	ipsPath := filepath.Join(outDir, "vhost_targets.txt")
	outBase := filepath.Join(outDir, "vhost_results")
	outJSON := outBase + ".json"
	forbiddenJSON := outBase + "_403.json"

	var candidates []string
	for _, d := range domains {
		d = strings.TrimSpace(d)
		if d == "" {
			continue
		}
		for _, w := range words {
			w = strings.TrimSpace(w)
			if w == "" || strings.HasPrefix(w, "#") {
				continue
			}
			candidates = append(candidates, w+"."+d)
		}
	}
	if len(candidates) == 0 {
		warn("No vhost candidates to try, skipping vhost discovery")
		return 0, 0, 0
	}
	if err := writeLines(hostsPath, candidates); err != nil {
		warn("Could not write vhost candidate file: %v", err)
		return 0, 0, 0
	}
	if err := writeLines(ipsPath, domains); err != nil {
		warn("Could not write vhost target file: %v", err)
		return 0, 0, 0
	}

	vhostConcurrency := concurrency
	if vhostConcurrency > vhostConcurrencyCap {
		vhostConcurrency = vhostConcurrencyCap
	}
	vhostTimeout := timeout
	if vhostTimeout > vhostRequestTimeoutSeconds {
		vhostTimeout = vhostRequestTimeoutSeconds
	}

	vhosterArgs := []string{
		"-hosts", hostsPath,
		"-ips", ipsPath,
		"-output", outBase,
		"-timeout", strconv.Itoa(vhostTimeout),
		"-concurrency", strconv.Itoa(vhostConcurrency),
		"-silent",
	}
	rc := runGoTool(filepath.Join(repoRoot, "vhosts", "cmd", "vhoster"), vhosterArgs, logFile, live)

	forbiddenCount := 0
	if forbidden, err := readVhosterResults(forbiddenJSON); err != nil {
		warn("Could not read 403 results: %v", err)
	} else {
		forbiddenSanitized := sanitizeHostLines(forbidden)
		if err := writeLines(forbiddenPath, forbiddenSanitized); err != nil {
			warn("Could not write 403 hosts to %s: %v", forbiddenPath, err)
		} else {
			forbiddenCount = len(forbiddenSanitized)
		}
	}

	found, err := readVhosterResults(outJSON)
	if err != nil {
		warn("Could not read vhost discovery results: %v", err)
		return rc, 0, forbiddenCount
	}

	sanitized := sanitizeHostLines(found)
	if err := writeLines(vhostSubsPath, sanitized); err != nil {
		warn("Could not write discovered vhosts to %s: %v", vhostSubsPath, err)
		return rc, 0, forbiddenCount
	}
	if len(sanitized) == 0 {
		return rc, 0, forbiddenCount
	}
	if err := mergeSanitizedHosts(vhostSubsPath, subsPath); err != nil {
		warn("Could not merge discovered vhosts into subdomains: %v", err)
		return rc, 0, forbiddenCount
	}
	return rc, len(sanitized), forbiddenCount
}

// readVhosterResults reads vhoster's {"target": ["vhost1", "vhost2", ...]}
// output and flattens it into a deduplicated list of vhost names. A
// missing file (nothing found, or the stage failed before writing one) is
// not an error -- it just means no vhosts to merge.
func readVhosterResults(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var byTarget map[string][]string
	if err := json.Unmarshal(data, &byTarget); err != nil {
		return nil, err
	}

	seen := make(map[string]struct{})
	var out []string
	for _, hosts := range byTarget {
		for _, h := range hosts {
			h = strings.TrimSpace(h)
			if h == "" {
				continue
			}
			if _, ok := seen[h]; ok {
				continue
			}
			seen[h] = struct{}{}
			out = append(out, h)
		}
	}
	return out, nil
}
