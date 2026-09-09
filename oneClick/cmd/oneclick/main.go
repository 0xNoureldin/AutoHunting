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
//	go run . -d example.com -port-scan             // TCP-connect port scan of discovered subdomains
//	go run . -resume oneClick/results/example.com_20260909_030405 // resume an interrupted run
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
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
  go run . -resume <dir>     Resume a previous (e.g. interrupted) run from its output directory

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
                              downloads, or -sw), reporting hosts whose response is confirmed,
                              against a live control probe in the same target zone, to be
                              genuinely different -- not just "status happens to be 403" or
                              "looks different from a stale baseline", which is what a WAF/rate
                              limit triggered mid-scan (or a target that 403s every unconfigured
                              name in its own zone) would otherwise turn every candidate into.
                              Finds vhosts
                              that exist only in the server's own routing config, with no DNS
                              record at all -- invisible to every other technique here. Off by
                              default; independent of -active, -mutations, -fuzz-subs, and
                              -fuzz-urls, and can be combined with any of them.
  -sw, -subs-wordlist <path> Use this wordlist for subdomain fuzzing/vhost discovery instead of
                              downloading one (implies -fuzz-subs)
  -uw, -urls-wordlist <path> Use this wordlist for URL fuzzing instead of downloading one
                              (implies -fuzz-urls)
  -ps, -port-scan             Enable TCP-connect port scanning across every discovered
                              subdomain. Scans the top 100 most common ports by default;
                              see -all-ports and -ports to scan differently. Only "notable"
                              open ports -- not 80/443/8080/8443, the common web ports
                              already covered elsewhere -- are written to ports.txt and
                              merged into subdomains.txt (as host:port, so URL enumeration
                              also targets that exact port). Off by default; independent of
                              every other stage, and can be combined with any of them.
  -ap, -all-ports             Scan all 65535 ports instead of the default top 100 (implies
                              -port-scan; ignored if -ports is also set).
  -ports <spec>               Scan this specific comma-separated list of ports and/or port
                              ranges instead of the default top 100 (e.g. 80,443,8000-8100).
                              Implies -port-scan and overrides -all-ports.
  -c, -concurrency <n>       Concurrency used across stages (default: 10)
  -t, -timeout <seconds>     Per-request timeout used across stages (default: 60, 300 with
                              -active, -fuzz-subs, -fuzz-urls, or -vhost)
  -lv, -live                  Stream each stage's live output to the terminal as it runs, not
                              just to the log file. Off by default (quiet, log-file-only).
  -qs, -quiet-stages          With -live, suppress each stage's raw internal output (every
                              discovery/error line a sub-tool logs as it runs) from the
                              terminal, while still printing oneClick's own stage banners and
                              the summary line after each stage finishes. The full raw output
                              is always written to the log file regardless -- this only
                              affects what's mirrored to the terminal. No effect without
                              -live (nothing streams to the terminal either way).
  -r, -resume <dir>          Resume an interrupted run from its output directory (the one
                              printed as "output:" and in the interrupt message). Skips
                              every pipeline phase (subdomain enumeration, vhost discovery,
                              403 detection, port scanning, URL enumeration, secret scanning)
                              that already finished, and continues with whatever's left.
                              Restores the original run's target and flags automatically --
                              don't combine -resume with any other flag.
  -h, -help                  Show this help

After every subdomain is known (from passive sources, DNS brute-force, and vhost discovery
alike), every one of them is probed directly for a 403 Forbidden response -- always, not
gated behind any flag above. Combined with -vhost's own findings and deduped, this becomes
403.txt, which is then merged into subdomains.txt: a 403 usually means the host exists and
is worth a closer look, not that it doesn't exist, so it gets the same downstream treatment
(URL enumeration, port scanning) as anything else discovered.

Examples:
  go run . -d example.com
  go run . -f domains.txt -o results/acme
  go run . -d example.com -active -c 20
  go run . -d example.com -fuzz-subs
  go run . -d example.com -fuzz-urls
  go run . -d example.com -fuzz-subs -sw my-subs.txt -fuzz-urls -uw my-paths.txt
  go run . -d example.com -vhost
  go run . -d example.com -active -mutations -vhost -live
  go run . -d example.com -port-scan
  go run . -d example.com -port-scan -all-ports
  go run . -d example.com -port-scan -ports 1-1000,8080,8443
  go run . -d example.com -fuzz-subs -vhost -live -quiet-stages  // live progress, no per-item spam
  go run . -d example.com -o results/example -active -fs -fu -vh -ps -lv -c 50
  go run . -resume oneClick/results/example.com_20260909_030405  // pick up an interrupted run
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
	var quietStages bool
	var mutations bool
	var vhost bool
	var portScan, allPorts bool
	var portsSpec string
	var subsWordlistOverride, urlsWordlistOverride string
	var resumeDir string
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
	fs.BoolVar(&portScan, "ps", false, "")
	fs.BoolVar(&portScan, "port-scan", false, "")
	fs.BoolVar(&allPorts, "ap", false, "")
	fs.BoolVar(&allPorts, "all-ports", false, "")
	fs.StringVar(&portsSpec, "ports", "", "")
	fs.BoolVar(&live, "live", false, "")
	fs.BoolVar(&live, "lv", false, "")
	fs.BoolVar(&quietStages, "quiet-stages", false, "")
	fs.BoolVar(&quietStages, "qs", false, "")
	fs.StringVar(&resumeDir, "resume", "", "")
	fs.StringVar(&resumeDir, "r", "", "")
	fs.BoolVar(&help, "h", false, "")
	fs.BoolVar(&help, "help", false, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		return 1
	}
	if help {
		usage()
		return 0
	}
	var explicitFlags []string
	fs.Visit(func(f *flag.Flag) {
		explicitFlags = append(explicitFlags, f.Name)
		if f.Name == "t" || f.Name == "timeout" {
			timeoutSet = true
		}
	})

	if resumeDir != "" {
		for _, name := range explicitFlags {
			if name == "resume" || name == "r" {
				continue
			}
			fail("-resume restores the original run's settings automatically; don't combine it with other flags (got -%s)", name)
			return 1
		}

		st, err := loadRunState(resumeDir)
		if err != nil {
			fail("Could not load resume state from %s: %v", resumeDir, err)
			return 1
		}
		cfg := st.Config
		domain = cfg.Domain
		domainFile = cfg.DomainFile
		active = cfg.Active
		concurrency = cfg.Concurrency
		timeout = cfg.Timeout
		timeoutSet = cfg.TimeoutSet
		fuzzSubs = cfg.FuzzSubs
		fuzzUrls = cfg.FuzzUrls
		mutations = cfg.Mutations
		vhost = cfg.Vhost
		portScan = cfg.PortScan
		allPorts = cfg.AllPorts
		portsSpec = cfg.PortsSpec
		live = cfg.Live
		quietStages = cfg.QuietStages
		subsWordlistOverride = cfg.SubsWordlistOverride
		urlsWordlistOverride = cfg.UrlsWordlistOverride
		outputDir = resumeDir
	}

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
	// Asking for all ports or a specific port spec is a clear signal of
	// intent, so it enables the port-scanning stage even without -port-scan.
	if allPorts || portsSpec != "" {
		portScan = true
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

	// st is the resume checkpoint for this output directory: loaded back
	// from a previous run when -resume was given (its Completed phases
	// tell the pipeline below what to skip), or freshly created and
	// immediately saved otherwise, so that even an interruption before
	// any phase finishes can still be resumed with the right config.
	var st *runState
	if resumeDir != "" {
		st, err = loadRunState(outputDir)
		if err != nil {
			fail("Could not load resume state from %s: %v", outputDir, err)
			return 1
		}
		ok("Resuming previous run in %s", outputDir)
	} else {
		st = newRunState(outputDir, runConfig{
			Domain:               domain,
			DomainFile:           domainFile,
			Active:               active,
			Concurrency:          concurrency,
			Timeout:              timeout,
			TimeoutSet:           timeoutSet,
			FuzzSubs:             fuzzSubs,
			FuzzUrls:             fuzzUrls,
			Mutations:            mutations,
			Vhost:                vhost,
			PortScan:             portScan,
			AllPorts:             allPorts,
			PortsSpec:            portsSpec,
			Live:                 live,
			QuietStages:          quietStages,
			SubsWordlistOverride: subsWordlistOverride,
			UrlsWordlistOverride: urlsWordlistOverride,
		})
		if err := st.save(); err != nil {
			fail("Could not write resume state: %v", err)
			return 1
		}
	}

	// A signal doesn't stop any sub-tool subprocess already running --
	// Ctrl+C delivers SIGINT to this whole foreground process group, so
	// the subprocess dies on its own too -- this just makes sure the user
	// sees how to pick the run back up instead of losing that information
	// when the terminal returns to a bare prompt.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println()
		warn("Interrupted -- progress so far is saved. Resume with:")
		fmt.Printf("  go run . -resume %s\n", outputDir)
		os.Exit(130)
	}()

	logPath := filepath.Join(outputDir, "oneclick.log")
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fail("Could not open log file: %v", err)
		return 1
	}
	defer logFile.Close()
	if resumeDir != "" {
		fmt.Fprintf(logFile, "\n=== Resumed at %s ===\n", time.Now().UTC().Format(time.RFC3339))
	}

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

	// stageLive gates only the raw, unfiltered stdout/stderr of each
	// sub-tool subprocess (discovery/error logs among it) being mirrored
	// to the terminal. quiet-stages overrides -live for that mirror alone
	// -- oneClick's own stage banners and per-stage summaries (step/ok/
	// warn/logf) are printed directly by this process and always show
	// regardless, and the full raw output always still goes to the log
	// file either way (see runGoTool).
	stageLive := live && !quietStages

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
	fmt.Printf("  port scan:   %s\n", portScanStatus(portScan, allPorts, portsSpec))
	fmt.Printf("  live logs:   %s\n", liveLogsStatus(live, quietStages))
	fmt.Printf("  concurrency: %d\n", concurrency)
	fmt.Printf("  timeout:     %ds\n", timeout)
	fmt.Printf("  output:      %s\n", outputDir)

	subsPath := filepath.Join(outputDir, "subdomains.txt")
	vhostSubsPath := filepath.Join(outputDir, "vhost_subdomains.txt")
	vhostForbiddenPath := filepath.Join(outputDir, "vhost_403.txt")
	forbiddenPath := filepath.Join(outputDir, "403.txt")
	urlsPath := filepath.Join(outputDir, "urls.txt")
	jsPath := filepath.Join(outputDir, "js_urls.txt")
	secretsPath := filepath.Join(outputDir, "secrets.json")
	portsPath := filepath.Join(outputDir, "ports.txt")

	var activeFlag []string
	if active {
		activeFlag = []string{"-active"}
	}

	// -------------------------------------------------------------------
	// Stage 1: Subdomain enumeration (SubEnum)
	// -------------------------------------------------------------------
	step("Stage 1/3: Subdomain enumeration")
	subEnumRC := 0
	if st.Completed.Subdomains {
		ok("Already completed (resumed), skipping")
	} else {
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
		// subsWordlist is also prepared for -vhost alone, which must NOT
		// imply SubEnum's own DNS brute-force -- only pass -w through when
		// the user actually asked for -fuzz-subs (or -sw, which implies
		// it above).
		if fuzzSubs && subsWordlist != "" {
			subEnumArgs = append(subEnumArgs, "-w", subsWordlist)
		}
		if mutations {
			subEnumArgs = append(subEnumArgs, "-mutations")
		}
		subEnumRC = runGoTool(filepath.Join(repoRoot, "SubEnum", "cmd", "subenum"), subEnumArgs, logFile, stageLive)

		// Always seed the discovered subdomains with the original
		// target(s) so later stages still have something to work with
		// even if enumeration finds nothing, and drop any garbage lines a
		// flaky source may inject.
		if err := mergeSanitizedHosts(inputDomainsPath, subsPath); err != nil {
			fail("Could not merge subdomain results: %v", err)
			return 1
		}
		if err := st.markDone(func(c *completedPhases) { c.Subdomains = true }); err != nil {
			warn("Could not save resume state: %v", err)
		}
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
	vhostCount, vhostForbiddenCount := 0, 0
	if vhost {
		if st.Completed.Vhost {
			vhostCount = countNonEmptyLines(vhostSubsPath)
			vhostForbiddenCount = countNonEmptyLines(vhostForbiddenPath)
			subsCount = countNonEmptyLines(subsPath)
			ok("Already completed (resumed), skipping: %d vhost(s), %d 403(s)", vhostCount, vhostForbiddenCount)
		} else {
			var vhostRC int
			vhostRC, vhostCount, vhostForbiddenCount = runVhostFuzz(repoRoot, rawDomains, subsWordlist, subsPath, vhostSubsPath, vhostForbiddenPath, concurrency, timeout, logFile, stageLive)
			subsCount = countNonEmptyLines(subsPath)
			if vhostRC != 0 {
				warn("vhost discovery exited with an error (see %s)", logPath)
			} else if vhostCount == 0 {
				ok("No vhosts discovered")
			} else {
				ok("Discovered %d vhost(s) -> %s (merged into %s, now %d total)", vhostCount, vhostSubsPath, subsPath, subsCount)
			}
			if vhostForbiddenCount > 0 {
				ok("%d candidate(s) returned a distinct 403 Forbidden -> %s", vhostForbiddenCount, vhostForbiddenPath)
			}
			if err := st.markDone(func(c *completedPhases) { c.Vhost = true }); err != nil {
				warn("Could not save resume state: %v", err)
			}
		}
	}
	// Always leave vhost_subdomains.txt and vhost_403.txt in place (empty
	// if -vhost wasn't used or nothing was found), so they're reliable
	// paths to reference rather than sometimes missing.
	touchFile(vhostSubsPath)
	touchFile(vhostForbiddenPath)

	// 403 detection across every discovered subdomain so far (always
	// runs, regardless of which discovery techniques were used): a direct
	// probe of the confirmed subdomain list, on each host's own name --
	// no baseline needed, since (unlike a vhost wordlist guess) every
	// entry here is already a confirmed, real subdomain from passive
	// sources, DNS brute-force, or vhost discovery merged in above.
	// Combined with vhost's own (DNS-less) 403 findings and deduped, then
	// merged into subdomains.txt so a 403-gated host gets the same
	// downstream treatment as anything else discovered -- a 403 usually
	// means the host exists and is worth a closer look, not that it
	// doesn't exist.
	step("Checking for 403 Forbidden across all subdomains")
	forbiddenCount := 0
	if st.Completed.Forbidden {
		forbiddenCount = countNonEmptyLines(forbiddenPath)
		subsCount = countNonEmptyLines(subsPath)
		ok("Already completed (resumed), skipping: %d 403(s)", forbiddenCount)
	} else {
		vhostForbidden, err := readLines(vhostForbiddenPath)
		if err != nil && !os.IsNotExist(err) {
			warn("Could not read %s: %v", vhostForbiddenPath, err)
		}
		allSubs, err := readLines(subsPath)
		if err != nil {
			warn("Could not read %s for 403 probing: %v", subsPath, err)
		}
		directForbidden := probeSubdomainsForForbidden(allSubs, concurrency, timeout)
		combined := sanitizeHostLines(append(vhostForbidden, directForbidden...))
		if err := writeLines(forbiddenPath, combined); err != nil {
			warn("Could not write %s: %v", forbiddenPath, err)
		} else {
			forbiddenCount = len(combined)
		}
		if forbiddenCount > 0 {
			if err := mergeSanitizedHosts(forbiddenPath, subsPath); err != nil {
				warn("Could not merge 403 hosts into %s: %v", subsPath, err)
			} else {
				subsCount = countNonEmptyLines(subsPath)
			}
			ok("%d subdomain(s) returned 403 Forbidden -> %s (merged into %s, now %d total)", forbiddenCount, forbiddenPath, subsPath, subsCount)
		} else {
			ok("No 403 Forbidden responses found")
		}
		if err := st.markDone(func(c *completedPhases) { c.Forbidden = true }); err != nil {
			warn("Could not save resume state: %v", err)
		}
	}
	touchFile(forbiddenPath)

	// Port scanning (optional, off by default): a TCP-connect scan across
	// every discovered subdomain (including any found via vhost
	// discovery). Catches non-web services and non-standard ports that
	// URL enumeration, which only ever looks at http(s) endpoints, would
	// never see. Only "notable" ports (not 80/443/8080/8443, the common
	// web ports already covered elsewhere) are kept, and merged into
	// subdomains.txt as host:port so URL enumeration also targets that
	// specific port.
	portsCount := 0
	portScanRC := 0
	if portScan {
		step("Port scanning")
		if st.Completed.PortScan {
			portsCount = countNonEmptyLines(portsPath)
			subsCount = countNonEmptyLines(subsPath)
			ok("Already completed (resumed), skipping: %d notable open port(s)", portsCount)
		} else {
			var totalPorts int
			portScanRC, totalPorts, portsCount = runPortScan(repoRoot, subsPath, portsPath, portsSpec, allPorts, concurrency, timeout, logFile, stageLive)
			subsCount = countNonEmptyLines(subsPath)
			if portScanRC != 0 {
				warn("portScanner exited with an error (see %s)", logPath)
			} else if portsCount == 0 {
				ok("No notable open ports found (%d total, all on 80/443/8080/8443)", totalPorts)
			} else {
				ok("Found %d notable open port(s) (%d total) -> %s (merged into %s, now %d total)", portsCount, totalPorts, portsPath, subsPath, subsCount)
			}
			if err := st.markDone(func(c *completedPhases) { c.PortScan = true }); err != nil {
				warn("Could not save resume state: %v", err)
			}
		}
	}
	// Always leave ports.txt in place (empty if -port-scan wasn't used or
	// nothing notable was found), so it's a reliable path to reference
	// rather than sometimes missing.
	touchFile(portsPath)

	// -------------------------------------------------------------------
	// Stage 2: URL enumeration (URLEnum)
	// -------------------------------------------------------------------
	step("Stage 2/3: URL enumeration")
	urlEnumRC := 0
	if st.Completed.URLEnum {
		ok("Already completed (resumed), skipping")
	} else {
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
		urlEnumRC = runGoTool(filepath.Join(repoRoot, "URLEnum", "cmd", "URLEnum"), urlEnumArgs, logFile, stageLive)
		if err := st.markDone(func(c *completedPhases) { c.URLEnum = true }); err != nil {
			warn("Could not save resume state: %v", err)
		}
	}

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
	jsAnalyzerRC := 0
	var jsCount int
	if st.Completed.Secrets {
		jsCount = countNonEmptyLines(jsPath)
		ok("Already completed (resumed), skipping -> %s", secretsPath)
	} else {
		if err := filterJSURLs(urlsPath, jsPath); err != nil {
			fail("Could not filter JS URLs: %v", err)
			return 1
		}
		jsCount = countNonEmptyLines(jsPath)
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
			jsAnalyzerRC = runGoTool(filepath.Join(repoRoot, "jsAnalyzer", "cmd"), jsAnalyzerArgs, logFile, stageLive)
			if jsAnalyzerRC != 0 {
				warn("jsAnalyzer exited with an error (see %s)", logPath)
			} else {
				ok("Secret scan results -> %s", secretsPath)
			}
		}
		if err := st.markDone(func(c *completedPhases) { c.Secrets = true }); err != nil {
			warn("Could not save resume state: %v", err)
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
			"port scan:         %s\n"+
			"generated:         %s\n"+
			"subdomains found:  %d   (%s)\n"+
			"  ...via vhost:    %d   (%s)\n"+
			"403 found:         %d   (%s)\n"+
			"  ...via vhost:    %d   (%s)\n"+
			"urls found:        %d   (%s)\n"+
			"js files found:    %d   (%s)\n"+
			"secrets output:    %s\n"+
			"notable ports:     %d   (%s)\n"+
			"full log:          %s\n",
		strings.Join(rawDomains, ","),
		modeShort,
		onOff(mutations),
		wordlistStatus(fuzzSubs, subsWordlist),
		wordlistStatus(fuzzUrls, urlsWordlist),
		wordlistStatus(vhost, subsWordlist),
		portScanStatus(portScan, allPorts, portsSpec),
		time.Now().UTC().Format(time.RFC3339),
		subsCount, subsPath,
		vhostCount, vhostSubsPath,
		forbiddenCount, forbiddenPath,
		vhostForbiddenCount, vhostForbiddenPath,
		urlsCount, urlsPath,
		jsCount, jsPath,
		secretsPath,
		portsCount, portsPath,
		logPath,
	)
	if err := os.WriteFile(summaryPath, []byte(summary), 0o644); err != nil {
		fail("Could not write summary: %v", err)
		return 1
	}
	fmt.Print(summary)

	step("Done")
	fmt.Printf("Results saved in: %s%s%s\n", bold, outputDir, reset)

	if subEnumRC != 0 || urlEnumRC != 0 || jsAnalyzerRC != 0 || portScanRC != 0 {
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
	return "", fmt.Errorf("could not locate the AutoHunting repo root (expected SubEnum, URLEnum, jsAnalyzer, vhosts and portScanner as siblings)")
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
	for _, sub := range []string{"SubEnum", "URLEnum", "jsAnalyzer", "vhosts", "portScanner"} {
		info, err := os.Stat(filepath.Join(dir, sub))
		if err != nil || !info.IsDir() {
			return false
		}
	}
	return true
}

// hostnameRe accepts a bare hostname or, so notable-port discoveries can
// be merged in as "host:port" and still reach URL enumeration targeting
// that exact port (see runPortScan), one with a trailing :port (1-5
// digits -- an approximation of the 1-65535 range, precise enough for
// sanitizing against injected garbage without a separate numeric check).
var hostnameRe = regexp.MustCompile(
	`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+(:[0-9]{1,5})?$`,
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

// liveLogsStatus describes the -live/-quiet-stages combination: off (the
// default, nothing streams), on (full raw stage output streams), or on
// but quieted (stage banners/summaries only, raw per-item stage output
// suppressed from the terminal -- though always still written in full to
// the log file).
func liveLogsStatus(live, quietStages bool) string {
	switch {
	case !live:
		return "off"
	case quietStages:
		return "on (stage banners/summaries only, see quiet-stages)"
	default:
		return "on"
	}
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
