// Command oneclick is a one-command recon pipeline for AutoHunting.
//
// Give it a domain (or a file of domains) and it chains together:
//  1. SubEnum    -> subdomain enumeration
//  2. URLEnum    -> URL enumeration on the discovered subdomains
//  3. jsAnalyzer -> secret scanning on the discovered .js files
//
// Usage (run from this directory):
//
//	go run . -d example.com
//	go run . -f domains.txt
//	go run . -d example.com -active -o /tmp/out
//	go run . -d example.com -fuzz-subs             // wordlist-based subdomain fuzzing
//	go run . -d example.com -fuzz-urls             // wordlist-based URL fuzzing
//	go run . -d example.com -fuzz-subs -fuzz-urls  // both
//	go run . -d example.com -vhost                 // Host-header vhost discovery
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var (
	bold, dim, green, yellow, red, cyan, reset string
)

func init() {
	if os.Getenv("NO_COLOR") == "" {
		bold, dim = "\x1b[1m", "\x1b[2m"
		green, yellow, red, cyan = "\x1b[32m", "\x1b[33m", "\x1b[31m", "\x1b[36m"
		reset = "\x1b[0m"
	}
}

func logf(format string, a ...any) {
	fmt.Printf("%s[%s]%s %s\n", dim, time.Now().Format("15:04:05"), reset, fmt.Sprintf(format, a...))
}
func step(format string, a ...any) {
	fmt.Printf("\n%s%s==> %s%s\n", bold, cyan, fmt.Sprintf(format, a...), reset)
}
func ok(format string, a ...any) {
	fmt.Printf("%s[ok]%s %s\n", green, reset, fmt.Sprintf(format, a...))
}
func warn(format string, a ...any) {
	fmt.Printf("%s[!]%s %s\n", yellow, reset, fmt.Sprintf(format, a...))
}
func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%s[x]%s %s\n", red, reset, fmt.Sprintf(format, a...))
}

func usage() {
	fmt.Fprintf(os.Stderr, `%soneClick%s - one command recon pipeline (subdomains -> URLs -> JS secrets)

Usage:
  go run . -d <domain>       Run the pipeline against a single domain
  go run . -f <file>         Run the pipeline against a file of domains (one per line)

Options:
  -d, -domain <domain>      Target domain, or comma separated domains
  -f, -file <path>          File with a list of domains, one per line
  -o, -output <dir>         Output directory (default: oneClick/results/<target>_<timestamp>)
  -a, -active                Enable active enumeration (slower, deeper: zone transfer, crawling,
                              headless browsing). Off by default for a fast passive-only run.
  -mu, -mutations             Enable alterx permutation-based subdomain guessing (e.g. dev-api,
                              api-dev from a known subdomain). Off by default; independent of
                              -active, -fuzz-subs, and -fuzz-urls, and can be combined with any.
  -fs, -fuzz-subs             Enable wordlist-based DNS brute-force fuzzing for subdomain
                              enumeration. Downloads and caches a well-known SecLists subdomain
                              wordlist on first use (oneClick/wordlists/), unless -sw is given.
                              Off by default; independent of -active, -mutations, and -fuzz-urls,
                              and can be combined with any of them.
  -fu, -fuzz-urls             Enable wordlist-based path/content fuzzing for URL enumeration.
                              Downloads and caches a well-known SecLists content wordlist on
                              first use (oneClick/wordlists/), unless -uw is given. Off by
                              default; independent of -active, -mutations, and -fuzz-subs, and
                              can be combined with any of them.
  -vh, -vhost                 Enable virtual host discovery: probes each target directly over
                              HTTP(S) with the Host header swapped to "word.domain" for every
                              entry in the subdomain wordlist (same one -fuzz-subs uses/
                              downloads, or -sw), reporting hosts whose response genuinely
                              differs. Finds vhosts that exist only in the server's own routing
                              config, with no DNS record at all -- invisible to every other
                              technique here. Off by default; independent of -active,
                              -mutations, -fuzz-subs, and -fuzz-urls, and can be combined with
                              any of them.
  -sw, -subs-wordlist <path> Use this wordlist for subdomain fuzzing/vhost discovery instead of
                              downloading one (implies -fuzz-subs)
  -uw, -urls-wordlist <path> Use this wordlist for URL fuzzing instead of downloading one
                              (implies -fuzz-urls)
  -c, -concurrency <n>       Concurrency used across stages (default: 10)
  -t, -timeout <seconds>     Per-request timeout used across stages (default: 60, 300 with
                              -active, -fuzz-subs, -fuzz-urls, or -vhost)
  -lv, -live                  Stream each stage's live output to the terminal as it runs, not
                              just to the log file. Off by default (quiet, log-file-only).
  -h, -help                  Show this help

Examples:
  go run . -d example.com
  go run . -f domains.txt -o results/acme
  go run . -d example.com -active -c 20
  go run . -d example.com -fuzz-subs
  go run . -d example.com -fuzz-urls
  go run . -d example.com -fuzz-subs -sw my-subs.txt -fuzz-urls -uw my-paths.txt
  go run . -d example.com -vhost
  go run . -d example.com -active -mutations -vhost -live
`, bold, reset)
}

func main() {
	os.Exit(run())
}

func run() int {
	var domain, domainFile, outputDir string
	var active bool
	var concurrency int
	var timeout int
	var help bool
	var fuzzSubs, fuzzUrls bool
	var live bool
	var mutations bool
	var vhost bool
	var subsWordlistOverride, urlsWordlistOverride string
	timeoutSet := false

	fs := flag.NewFlagSet("oneclick", flag.ContinueOnError)
	fs.Usage = usage
	fs.StringVar(&domain, "d", "", "")
	fs.StringVar(&domain, "domain", "", "")
	fs.StringVar(&domainFile, "f", "", "")
	fs.StringVar(&domainFile, "file", "", "")
	fs.StringVar(&outputDir, "o", "", "")
	fs.StringVar(&outputDir, "output", "", "")
	fs.BoolVar(&active, "a", false, "")
	fs.BoolVar(&active, "active", false, "")
	fs.IntVar(&concurrency, "c", 10, "")
	fs.IntVar(&concurrency, "concurrency", 10, "")
	fs.IntVar(&timeout, "t", 60, "")
	fs.IntVar(&timeout, "timeout", 60, "")
	fs.BoolVar(&fuzzSubs, "fs", false, "")
	fs.BoolVar(&fuzzSubs, "fuzz-subs", false, "")
	fs.BoolVar(&fuzzUrls, "fu", false, "")
	fs.BoolVar(&fuzzUrls, "fuzz-urls", false, "")
	fs.StringVar(&subsWordlistOverride, "sw", "", "")
	fs.StringVar(&subsWordlistOverride, "subs-wordlist", "", "")
	fs.StringVar(&urlsWordlistOverride, "uw", "", "")
	fs.StringVar(&urlsWordlistOverride, "urls-wordlist", "", "")
	fs.BoolVar(&mutations, "mu", false, "")
	fs.BoolVar(&mutations, "mutations", false, "")
	fs.BoolVar(&vhost, "vh", false, "")
	fs.BoolVar(&vhost, "vhost", false, "")
	fs.BoolVar(&live, "live", false, "")
	fs.BoolVar(&live, "lv", false, "")
	fs.BoolVar(&help, "h", false, "")
	fs.BoolVar(&help, "help", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if help {
		usage()
		return 0
	}
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "t" || f.Name == "timeout" {
			timeoutSet = true
		}
	})

	if domain == "" && domainFile == "" {
		fail("You must provide either -d <domain> or -f <file>")
		usage()
		return 1
	}
	if domain != "" && domainFile != "" {
		fail("Use either -d or -f, not both")
		return 1
	}
	if domainFile != "" {
		info, err := os.Stat(domainFile)
		if err != nil || info.Size() == 0 {
			fail("Domain file not found or empty: %s", domainFile)
			return 1
		}
	}
	if _, err := exec.LookPath("go"); err != nil {
		fail("Go is required but was not found in PATH")
		return 1
	}
	// Passing a custom wordlist is a clear signal of intent, so it enables
	// the corresponding fuzzing stage even without the -fuzz-subs/-fuzz-urls
	// flag.
	if subsWordlistOverride != "" {
		fuzzSubs = true
	}
	if urlsWordlistOverride != "" {
		fuzzUrls = true
	}

	if (active || fuzzSubs || fuzzUrls || vhost) && !timeoutSet {
		// All are deep/slow techniques: -active budgets a full crawl or
		// headless page load per seed, and each fuzz/vhost stage budgets
		// working through a wordlist of thousands of candidates per seed
		// (subdomain DNS brute-force has its own short, fixed per-query
		// timeout regardless of this).
		timeout = 300
	}

	repoRoot, err := findRepoRoot()
	if err != nil {
		fail("%v", err)
		return 1
	}

	var subsWordlist, urlsWordlist string
	if fuzzSubs || fuzzUrls || vhost {
		step("Preparing fuzzing wordlists")
		cacheDir := filepath.Join(repoRoot, "oneClick", "wordlists")

		if fuzzSubs || vhost {
			if subsWordlistOverride != "" {
				subsWordlist = subsWordlistOverride
				ok("Using subdomain wordlist -> %s", subsWordlist)
			} else if p, err := ensureWordlist(cacheDir, "subdomains.txt", defaultSubdomainWordlistURL); err != nil {
				warn("Could not prepare subdomain wordlist, subdomain fuzzing/vhost discovery disabled: %v", err)
			} else {
				subsWordlist = p
				ok("Subdomain wordlist ready -> %s", p)
			}
		}

		if fuzzUrls {
			if urlsWordlistOverride != "" {
				urlsWordlist = urlsWordlistOverride
				ok("Using URL wordlist -> %s", urlsWordlist)
			} else if p, err := ensureWordlist(cacheDir, "paths.txt", defaultPathWordlistURL); err != nil {
				warn("Could not prepare URL wordlist, URL fuzzing disabled: %v", err)
			} else {
				urlsWordlist = p
				ok("URL wordlist ready -> %s", p)
			}
		}
	}

	targetName := sanitizeName(domain)
	if targetName == "" {
		targetName = sanitizeName(filepath.Base(domainFile))
	}

	if outputDir == "" {
		outputDir = filepath.Join(repoRoot, "oneClick", "results",
			fmt.Sprintf("%s_%s", targetName, time.Now().Format("20060102_150405")))
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		fail("Could not create output directory: %v", err)
		return 1
	}
	if abs, err := filepath.Abs(outputDir); err == nil {
		outputDir = abs
	}

	logPath := filepath.Join(outputDir, "oneclick.log")
	logFile, err := os.Create(logPath)
	if err != nil {
		fail("Could not create log file: %v", err)
		return 1
	}
	defer logFile.Close()

	inputDomainsPath := filepath.Join(outputDir, "input_domains.txt")
	var rawDomains []string
	if domain != "" {
		for _, d := range strings.Split(domain, ",") {
			d = strings.TrimSpace(d)
			if d != "" {
				rawDomains = append(rawDomains, d)
			}
		}
	} else {
		lines, err := readLines(domainFile)
		if err != nil {
			fail("Could not read domain file: %v", err)
			return 1
		}
		for _, l := range lines {
			l = strings.TrimSpace(l)
			if l != "" {
				rawDomains = append(rawDomains, l)
			}
		}
	}
	if len(rawDomains) == 0 {
		fail("No valid domains found in input")
		return 1
	}
	if err := writeLines(inputDomainsPath, rawDomains); err != nil {
		fail("Could not write input domains: %v", err)
		return 1
	}

	mode, modeShort := "passive (fast)", "passive"
	if active {
		mode, modeShort = "active (deep, slower)", "active"
	}
	fmt.Printf("%soneClick recon pipeline%s\n", bold, reset)
	fmt.Printf("  targets:     %d domain(s)\n", len(rawDomains))
	fmt.Printf("  mode:        %s\n", mode)
	fmt.Printf("  mutations:   %s\n", onOff(mutations))
	fmt.Printf("  fuzz subs:   %s\n", wordlistStatus(fuzzSubs, subsWordlist))
	fmt.Printf("  fuzz urls:   %s\n", wordlistStatus(fuzzUrls, urlsWordlist))
	fmt.Printf("  vhost:       %s\n", wordlistStatus(vhost, subsWordlist))
	fmt.Printf("  live logs:   %s\n", onOff(live))
	fmt.Printf("  concurrency: %d\n", concurrency)
	fmt.Printf("  timeout:     %ds\n", timeout)
	fmt.Printf("  output:      %s\n", outputDir)

	subsPath := filepath.Join(outputDir, "subdomains.txt")
	vhostSubsPath := filepath.Join(outputDir, "vhost_subdomains.txt")
	urlsPath := filepath.Join(outputDir, "urls.txt")
	jsPath := filepath.Join(outputDir, "js_urls.txt")
	secretsPath := filepath.Join(outputDir, "secrets.json")

	var activeFlag []string
	if active {
		activeFlag = []string{"-active"}
	}

	// -------------------------------------------------------------------
	// Stage 1: Subdomain enumeration (SubEnum)
	// -------------------------------------------------------------------
	step("Stage 1/3: Subdomain enumeration")
	// DNS brute-force queries are cheap and parallelize far better than
	// HTTP work (a dead candidate can mean up to 8 sequential resolver
	// round trips), so a wordlist of thousands of candidates needs more
	// concurrency than the default to finish in reasonable time.
	subEnumConcurrency := concurrency
	if fuzzSubs && subsWordlist != "" && subEnumConcurrency < 50 {
		subEnumConcurrency = 50
	}
	subEnumArgs := append([]string{
		"-i", inputDomainsPath,
		"-o", subsPath,
		"-c", strconv.Itoa(subEnumConcurrency),
		"-timeout", strconv.Itoa(timeout),
	}, activeFlag...)
	// subsWordlist is also prepared for -vhost alone, which must NOT imply
	// SubEnum's own DNS brute-force -- only pass -w through when the user
	// actually asked for -fuzz-subs (or -sw, which implies it above).
	if fuzzSubs && subsWordlist != "" {
		subEnumArgs = append(subEnumArgs, "-w", subsWordlist)
	}
	if mutations {
		subEnumArgs = append(subEnumArgs, "-mutations")
	}
	subEnumRC := runGoTool(filepath.Join(repoRoot, "SubEnum", "cmd", "subenum"), subEnumArgs, logFile, live)

	// Always seed the discovered subdomains with the original target(s) so
	// later stages still have something to work with even if enumeration
	// finds nothing, and drop any garbage lines a flaky source may inject.
	if err := mergeSanitizedHosts(inputDomainsPath, subsPath); err != nil {
		fail("Could not merge subdomain results: %v", err)
		return 1
	}
	subsCount := countNonEmptyLines(subsPath)
	if subEnumRC != 0 {
		warn("SubEnum exited with an error (see %s), continuing with %d known host(s)", logPath, subsCount)
	} else {
		ok("Found %d unique subdomain(s) -> %s", subsCount, subsPath)
	}

	// Virtual host discovery: subdomains found via DNS (passive sources,
	// brute-force, permutation) all require a DNS record to exist. A vhost
	// that's only routed by the server's own config (nginx/Apache/an LB)
	// has no such record and is invisible to every technique above. This
	// probes the target(s) directly over HTTP(S) with the Host header
	// swapped to each wordlist candidate, keeping the same connection
	// target throughout -- the same effect as pinning the domain to an IP
	// in /etc/hosts and fuzzing the Host header, without touching system
	// DNS config.
	vhostCount := 0
	if vhost {
		var vhostRC int
		vhostRC, vhostCount = runVhostFuzz(repoRoot, rawDomains, subsWordlist, subsPath, vhostSubsPath, concurrency, timeout, logFile, live)
		subsCount = countNonEmptyLines(subsPath)
		if vhostRC != 0 {
			warn("vhost discovery exited with an error (see %s)", logPath)
		} else if vhostCount == 0 {
			ok("No vhosts discovered")
		} else {
			ok("Discovered %d vhost(s) -> %s (merged into %s, now %d total)", vhostCount, vhostSubsPath, subsPath, subsCount)
		}
	}
	// Always leave vhost_subdomains.txt in place (empty if -vhost wasn't
	// used or nothing was found), so it's a reliable path to reference
	// rather than sometimes missing.
	touchFile(vhostSubsPath)

	// -------------------------------------------------------------------
	// Stage 2: URL enumeration (URLEnum)
	// -------------------------------------------------------------------
	step("Stage 2/3: URL enumeration")
	urlEnumArgs := append([]string{
		"-i", subsPath, "-subs",
		"-o", urlsPath,
		"-pc", strconv.Itoa(concurrency),
		"-ac", strconv.Itoa(concurrency * 2),
		"-timeout", strconv.Itoa(timeout),
	}, activeFlag...)
	if urlsWordlist != "" {
		urlEnumArgs = append(urlEnumArgs, "-w", urlsWordlist)
	}
	urlEnumRC := runGoTool(filepath.Join(repoRoot, "URLEnum", "cmd", "URLEnum"), urlEnumArgs, logFile, live)

	touchFile(urlsPath)
	urlsCount := countNonEmptyLines(urlsPath)
	if urlEnumRC != 0 {
		warn("URLEnum exited with an error (see %s), continuing with %d known URL(s)", logPath, urlsCount)
	} else {
		ok("Found %d unique URL(s) -> %s", urlsCount, urlsPath)
	}

	// -------------------------------------------------------------------
	// Stage 3: JS secret scanning (jsAnalyzer)
	// -------------------------------------------------------------------
	step("Stage 3/3: JS secret scanning")
	if err := filterJSURLs(urlsPath, jsPath); err != nil {
		fail("Could not filter JS URLs: %v", err)
		return 1
	}
	jsCount := countNonEmptyLines(jsPath)
	jsAnalyzerRC := 0
	if jsCount == 0 {
		warn("No JS files found in URLEnum output, skipping secret scan")
		if err := os.WriteFile(secretsPath, []byte("[]\n"), 0o644); err != nil {
			fail("Could not write empty secrets file: %v", err)
			return 1
		}
	} else {
		logf("Scanning %d JS file(s) for secrets", jsCount)
		jsAnalyzerArgs := []string{
			"-i", jsPath,
			"-o", secretsPath,
			"-only", "secrets",
			"-c", strconv.Itoa(concurrency),
			"-timeout", strconv.Itoa(timeout),
		}
		jsAnalyzerRC = runGoTool(filepath.Join(repoRoot, "jsAnalyzer", "cmd"), jsAnalyzerArgs, logFile, live)
		if jsAnalyzerRC != 0 {
			warn("jsAnalyzer exited with an error (see %s)", logPath)
		} else {
			ok("Secret scan results -> %s", secretsPath)
		}
	}

	// -------------------------------------------------------------------
	// Summary
	// -------------------------------------------------------------------
	summaryPath := filepath.Join(outputDir, "SUMMARY.txt")
	summary := fmt.Sprintf(
		"oneClick recon summary\n"+
			"target(s):        %s\n"+
			"mode:              %s\n"+
			"mutations:         %s\n"+
			"fuzz subs:         %s\n"+
			"fuzz urls:         %s\n"+
			"vhost:             %s\n"+
			"generated:         %s\n"+
			"subdomains found:  %d   (%s)\n"+
			"  ...via vhost:    %d   (%s)\n"+
			"urls found:        %d   (%s)\n"+
			"js files found:    %d   (%s)\n"+
			"secrets output:    %s\n"+
			"full log:          %s\n",
		strings.Join(rawDomains, ","),
		modeShort,
		onOff(mutations),
		wordlistStatus(fuzzSubs, subsWordlist),
		wordlistStatus(fuzzUrls, urlsWordlist),
		wordlistStatus(vhost, subsWordlist),
		time.Now().UTC().Format(time.RFC3339),
		subsCount, subsPath,
		vhostCount, vhostSubsPath,
		urlsCount, urlsPath,
		jsCount, jsPath,
		secretsPath,
		logPath,
	)
	if err := os.WriteFile(summaryPath, []byte(summary), 0o644); err != nil {
		fail("Could not write summary: %v", err)
		return 1
	}
	fmt.Print(summary)

	step("Done")
	fmt.Printf("Results saved in: %s%s%s\n", bold, outputDir, reset)

	if subEnumRC != 0 || urlEnumRC != 0 || jsAnalyzerRC != 0 {
		warn("One or more stages reported errors, check %s for details", logPath)
		return 2
	}
	return 0
}

// runGoTool runs `go run .` in dir with the given args, sending combined
// stdout/stderr to logFile (and, when live is true, also streaming it to
// the terminal as it's produced instead of only being visible in the log
// file afterward), and returns the process exit code (0 on success,
// non-zero on failure, 1 if the process could not even start).
func runGoTool(dir string, args []string, logFile io.Writer, live bool) int {
	fmt.Fprintf(logFile, "\n--- go run . %s (in %s) ---\n", strings.Join(args, " "), dir)
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	cmd.Dir = dir
	out := logFile
	if live {
		out = io.MultiWriter(logFile, os.Stdout)
	}
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode()
		}
		fmt.Fprintf(logFile, "failed to run: %v\n", err)
		return 1
	}
	return 0
}

// findRepoRoot locates the AutoHunting repo root by walking up from the
// current working directory (covers `go run ./oneClick/cmd/oneclick ...`
// invoked from anywhere inside the repo) and, failing that, from this
// source file's own location (covers `cd oneClick/cmd/oneclick && go run .`).
func findRepoRoot() (string, error) {
	if wd, err := os.Getwd(); err == nil {
		if root, ok := searchUpwardForRepoRoot(wd); ok {
			return root, nil
		}
	}
	if execPath, err := os.Executable(); err == nil {
		if root, ok := searchUpwardForRepoRoot(filepath.Dir(execPath)); ok {
			return root, nil
		}
	}
	return "", fmt.Errorf("could not locate the AutoHunting repo root (expected SubEnum, URLEnum, jsAnalyzer and vhosts as siblings)")
}

func searchUpwardForRepoRoot(start string) (string, bool) {
	dir := start
	for {
		if isRepoRoot(dir) {
			return dir, true
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", false
		}
		dir = parent
	}
}

func isRepoRoot(dir string) bool {
	for _, sub := range []string{"SubEnum", "URLEnum", "jsAnalyzer", "vhosts"} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

var hostnameRe = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`,
)

// sanitizeHostLines keeps only lines that look like a valid hostname
// (dropping garbage a flaky/blocked source may have injected, such as
// error messages), dedupes, and sorts.
func sanitizeHostLines(lines []string) []string {
	seen := make(map[string]struct{})
	var hosts []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || !hostnameRe.MatchString(l) {
			continue
		}
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		hosts = append(hosts, l)
	}
	sort.Strings(hosts)
	return hosts
}

// mergeSanitizedHosts merges inputPath and subsPath, sanitizes the union
// (see sanitizeHostLines), and writes the result back to subsPath.
func mergeSanitizedHosts(inputPath, subsPath string) error {
	touchFile(subsPath)
	inputLines, err := readLines(inputPath)
	if err != nil {
		return err
	}
	subLines, err := readLines(subsPath)
	if err != nil {
		return err
	}

	hosts := sanitizeHostLines(append(inputLines, subLines...))
	return writeLines(subsPath, hosts)
}

var (
	jsIncludeRe = regexp.MustCompile(`(?i)\.js([?#].*)?$`)
	jsExcludeRe = regexp.MustCompile(`(?i)\.map([?#]|$)|\.json\.js`)
)

// filterJSURLs mirrors jsAnalyzer/GetJSOnlyCMD.txt: keep URLs that look
// like a .js file, drop source maps and .json.js false positives, dedupe
// and sort.
func filterJSURLs(urlsPath, jsPath string) error {
	lines, err := readLines(urlsPath)
	if err != nil {
		if os.IsNotExist(err) {
			lines = nil
		} else {
			return err
		}
	}

	seen := make(map[string]struct{})
	var jsURLs []string
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || !jsIncludeRe.MatchString(l) || jsExcludeRe.MatchString(l) {
			continue
		}
		if _, ok := seen[l]; ok {
			continue
		}
		seen[l] = struct{}{}
		jsURLs = append(jsURLs, l)
	}
	sort.Strings(jsURLs)
	return writeLines(jsPath, jsURLs)
}

// wordlistStatus reports the state of one independent fuzzing stage: off
// (not requested), on (a wordlist is ready to use), or unavailable (the
// user asked for it but no wordlist could be prepared -- see warnings
// printed during wordlist preparation).
func wordlistStatus(enabled bool, wordlist string) string {
	switch {
	case !enabled:
		return "off"
	case wordlist != "":
		return "on"
	default:
		return "requested, but unavailable (see warnings above)"
	}
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

func sanitizeName(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	out := b.String()
	if len(out) > 60 {
		out = out[:60]
	}
	return out
}

func readLines(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func writeLines(path string, lines []string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	for _, l := range lines {
		if _, err := w.WriteString(l + "\n"); err != nil {
			return err
		}
	}
	return w.Flush()
}

func countNonEmptyLines(path string) int {
	lines, err := readLines(path)
	if err != nil {
		return 0
	}
	count := 0
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			count++
		}
	}
	return count
}

func touchFile(path string) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.Create(path)
		if err == nil {
			f.Close()
		}
	}
}
