package headless

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
	"github.com/cyinnove/logify"
	"golang.org/x/net/publicsuffix"
)

type Options struct {
	Concurrency    int
	Timeout        time.Duration // per target
	Wait           time.Duration // after load
	ChromePath     string
	Headless       bool
	NoSandbox      bool
	DisableGPU     bool
	DisableDevShm  bool
	ExtraAllocator []chromedp.ExecAllocatorOption
}

func (o Options) withDefaults() Options {
	if o.Concurrency <= 0 {
		o.Concurrency = 3
	}
	if o.Timeout <= 0 {
		o.Timeout = 30 * time.Second
	}
	if o.Wait <= 0 {
		o.Wait = 8 * time.Second
	}
	if strings.TrimSpace(o.ChromePath) == "" {
    if runtime.GOOS == "windows" {
        o.ChromePath = `C:\Program Files\Google\Chrome\Application\chrome.exe`
    } else {
        o.ChromePath = "/usr/bin/google-chrome"
    }
}

	if !o.Headless {
		o.Headless = true
	}
	if !o.NoSandbox {
		o.NoSandbox = true
	}
	if !o.DisableGPU {
		o.DisableGPU = true
	}
	if !o.DisableDevShm {
		o.DisableDevShm = true
	}
	return o
}

// Enumerate scans a single start target and returns unique informational URLs.
func Enumerate(ctx context.Context, start string, includeSubdomains bool, opts Options) ([]string, error) {
	logify.Infof("Starting headless enumeration for %s (includeSubdomains=%v)", start, includeSubdomains)
	opts = opts.withDefaults()

	startURL := normalizeTarget(start)
	if startURL == "" {
		return nil, errors.New("empty start")
	}

	u0, err := url.Parse(startURL)
	if err != nil || u0.Host == "" {
		return nil, fmt.Errorf("invalid start url: %q", start)
	}

	// domain allow function
	var allowFn func(string) bool
	if includeSubdomains {
		rootETLD1 := etldPlusOne(u0.Hostname())
		if rootETLD1 == "" {
			return nil, fmt.Errorf("cannot compute eTLD+1 for %s", u0.Hostname())
		}
		allowFn = func(candidate string) bool {
			uu, err := url.Parse(candidate)
			return err == nil && etldPlusOne(uu.Hostname()) == rootETLD1
		}
	} else {
		rootHost := strings.ToLower(u0.Hostname())
		allowFn = func(candidate string) bool {
			uu, err := url.Parse(candidate)
			return err == nil && strings.ToLower(uu.Hostname()) == rootHost
		}
	}

	browserCtx, cancelBrowser := newBrowserContext(ctx, opts.ChromePath, opts)
	out, err := scanWithCollector(ctx, browserCtx, startURL, opts, allowFn)
	cancelBrowser()

	if err != nil && isChromeNotFound(err) {
		logify.Warningf("headless: Chrome not found at %q (%v) -- attempting to install it and retry", opts.ChromePath, err)
		resolvedPath, installErr := ensureChromeAvailable()
		if installErr != nil {
			return out, fmt.Errorf("%w (auto-install also failed: %v)", err, installErr)
		}

		logify.Infof("headless: retrying %s using %s", start, resolvedPath)
		opts.ChromePath = resolvedPath
		browserCtx, cancelBrowser = newBrowserContext(ctx, opts.ChromePath, opts)
		out, err = scanWithCollector(ctx, browserCtx, startURL, opts, allowFn)
		cancelBrowser()
	}

	return out, err
}

// newBrowserContext builds a fresh chromedp allocator+browser context using
// chromePath. chromedp bakes the executable path into the allocator at
// creation time, so retrying against a different (freshly installed or
// located) Chrome binary requires a brand new context rather than reusing
// the one whose launch just failed.
func newBrowserContext(ctx context.Context, chromePath string, opts Options) (context.Context, context.CancelFunc) {
	allocOpts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.ExecPath(chromePath),
		chromedp.Flag("headless", opts.Headless),
		chromedp.Flag("no-sandbox", opts.NoSandbox),
		chromedp.Flag("disable-gpu", opts.DisableGPU),
		chromedp.Flag("disable-dev-shm-usage", opts.DisableDevShm),
	)
	if len(opts.ExtraAllocator) > 0 {
		allocOpts = append(allocOpts, opts.ExtraAllocator...)
	}

	allocCtx, cancelAlloc := chromedp.NewExecAllocator(ctx, allocOpts...)
	browserCtx, cancelBrowser := chromedp.NewContext(allocCtx)
	return browserCtx, func() {
		cancelBrowser()
		cancelAlloc()
	}
}

// scanWithCollector runs scanTarget against startURL over browserCtx and
// collects every informational, in-scope URL it observes into a
// deduplicated slice. ctx (as opposed to browserCtx, which is derived from
// it) is used for the caller's own cancellation checks.
func scanWithCollector(ctx, browserCtx context.Context, startURL string, opts Options, allowFn func(string) bool) ([]string, error) {
	// results collector
	results := make(chan string, 2048)
	var (
		mu   sync.Mutex
		seen = map[string]struct{}{}
		out  = make([]string, 0, 512)
	)

	var collectorWG sync.WaitGroup
	collectorWG.Add(1)
	go func() {
		defer collectorWG.Done()
		for u := range results {
			mu.Lock()
			if _, ok := seen[u]; !ok {
				seen[u] = struct{}{}
				out = append(out, u)
			}
			mu.Unlock()
		}
	}()

	// bounded worker pool
	sem := make(chan struct{}, opts.Concurrency)
	errCh := make(chan error, 1)

	sem <- struct{}{}
	go func(target string) {
		defer func() { <-sem }()

		err := scanTarget(browserCtx, target, opts.Timeout, opts.Wait, func(raw string) {
			u := normalizeCapturedURL(raw)
			if u == "" || !isInformational(u) || !allowFn(u) {
				return
			}
			select {
			case results <- u:
			case <-ctx.Done():
			}
		})

		if err != nil {
			select {
			case errCh <- err:
			default:
			}
		}
	}(startURL)

	// wait for workers
	for i := 0; i < cap(sem); i++ {
		sem <- struct{}{}
	}

	close(results)
	collectorWG.Wait()

	select {
	case e := <-errCh:
		return out, e
	default:
	}

	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}

func scanTarget(browserCtx context.Context, targetURL string, perTargetTimeout, wait time.Duration, onURL func(string)) error {
	ctx, cancel := chromedp.NewContext(browserCtx)
	defer cancel()

	ctx, cancel = context.WithTimeout(ctx, perTargetTimeout)
	defer cancel()

	chromedp.ListenTarget(ctx, func(ev any) {
		if r, ok := ev.(*network.EventResponseReceived); ok && r.Response.URL != "" {
			onURL(r.Response.URL)
		}
	})

	return chromedp.Run(ctx,
		network.Enable(),
		chromedp.Navigate(targetURL),
		chromedp.WaitReady("body", chromedp.ByQuery),
		chromedp.Sleep(wait),
	)
}

func normalizeTarget(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		return s
	}
	return "https://" + s
}

func normalizeCapturedURL(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	u.Fragment = ""
	if u.Path != "/" && strings.HasSuffix(u.Path, "/") {
		u.Path = strings.TrimSuffix(u.Path, "/")
	}
	return u.String()
}

func isInformational(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil {
		return false
	}
	ext := strings.ToLower(path.Ext(u.Path))
	switch ext {
	case "", ".js", ".html", ".htm",
		".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
		".asp", ".aspx", ".ashx", ".asmx",
		".jsp", ".jspx", ".do", ".action",
		".mjs", ".json", ".xml", ".graphql", ".wsdl", ".yaml", ".yml", ".txt":
		return true
	default:
		return false
	}
}

func etldPlusOne(host string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	if host == "" {
		return ""
	}
	if strings.Contains(host, ":") {
		host = strings.Split(host, ":")[0]
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return etld1
}

// =========================
// Chrome auto-install
// =========================

// isChromeNotFound reports whether err is the "Chrome binary doesn't exist
// at the configured path" failure -- os/exec's fork/exec ENOENT, surfacing
// through chromedp as e.g. "fork/exec /usr/bin/google-chrome: no such file
// or directory" -- as opposed to a genuine navigation failure (DNS,
// timeout, TLS, target crashed, ...), which installing a browser can't fix
// and retrying would just waste time.
func isChromeNotFound(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound) {
		return true
	}
	var pathErr *os.PathError
	if errors.As(err, &pathErr) && pathErr.Op == "fork/exec" {
		return true
	}
	// Fallback string match: chromedp/the underlying browser library may
	// wrap the original error in ways errors.As can't see through, but
	// the OS-level message text is stable across those wrappers.
	msg := err.Error()
	return strings.Contains(msg, "fork/exec") && strings.Contains(msg, "no such file or directory")
}

// commonChromeBinaryNames are tried, in order, both to detect an
// already-installed browser under a name other than the hardcoded default
// (e.g. a distro that only ships "chromium") and to locate the binary a
// fresh install just produced.
var commonChromeBinaryNames = []string{
	"google-chrome",
	"google-chrome-stable",
	"chromium",
	"chromium-browser",
	"chrome",
}

// findExistingChrome returns the full path of the first Chrome/Chromium
// binary found on PATH under any of commonChromeBinaryNames, or "" if none
// is found. It doesn't check whether the binary actually runs -- see
// findWorkingChrome, which is what ensureChromeAvailable actually uses.
func findExistingChrome() string {
	for _, name := range commonChromeBinaryNames {
		if p, err := exec.LookPath(name); err == nil {
			return p
		}
	}
	return ""
}

// findWorkingChrome is like findExistingChrome but also verifies each
// candidate actually runs before accepting it, skipping past any that
// don't. This matters in practice: on Ubuntu, "apt-get install chromium"
// installs a transitional package that just wraps "snap install chromium"
// -- in a container without a working snapd (the common case) that
// produces a real, executable /usr/bin/chromium-browser that unconditionally
// fails with "requires the chromium snap to be installed" the moment it's
// run. Just checking PATH would report that as "Chrome is available" and
// leave the original failure to resurface, confusingly, one level down.
func findWorkingChrome() string {
	for _, name := range commonChromeBinaryNames {
		p, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if chromeBinaryWorks(p) {
			return p
		}
	}
	return ""
}

// chromeBinaryWorks reports whether running "<path> --version" succeeds --
// a fast, sandbox/flag-independent smoke test that doesn't need to launch
// an actual browser window or DevTools session.
func chromeBinaryWorks(path string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return exec.CommandContext(ctx, path, "--version").Run() == nil
}

var (
	chromeInstallOnce sync.Once
	chromeResolvedBin string
	chromeInstallErr  error
)

// ensureChromeAvailable finds or installs a Chrome/Chromium build and
// returns its path. It runs the actual detection/install work at most once
// per process (guarded by chromeInstallOnce): every seed/target that hits
// a missing-Chrome error after the first reuses the same cached result
// instead of re-attempting a package install once per URL.
func ensureChromeAvailable() (string, error) {
	chromeInstallOnce.Do(func() {
		if p := findWorkingChrome(); p != "" {
			chromeResolvedBin = p
			return
		}
		if err := installChrome(); err != nil {
			chromeInstallErr = err
			return
		}
		p := findWorkingChrome()
		if p == "" {
			chromeInstallErr = errors.New("a browser package was installed but doesn't run successfully (a snap-only package without a working snapd is a common cause on Ubuntu) -- install Chrome/Chromium manually and set -chrome-path")
			return
		}
		chromeResolvedBin = p
	})
	return chromeResolvedBin, chromeInstallErr
}

// installChrome installs a headless-capable Chromium/Chrome build using
// whatever this system provides, best-effort.
func installChrome() error {
	switch runtime.GOOS {
	case "linux":
		return installChromeLinux()
	case "darwin":
		return installChromeDarwin()
	default:
		return fmt.Errorf("automatic Chrome install isn't supported on %s -- install Chrome/Chromium manually and set -chrome-path", runtime.GOOS)
	}
}

// installChromeLinux tries several strategies, in order, stopping at the
// first that leaves a genuinely working browser on PATH (checked with
// findWorkingChrome after every attempt -- a package manager reporting
// success is not, by itself, good enough; see findWorkingChrome).
//
// Google Chrome's official .deb is tried first when apt-get is present:
// on Ubuntu, apt's own "chromium"/"chromium-browser" packages are just a
// transitional wrapper around "snap install chromium", which silently
// fails in the exact environments (containers, minimal servers) headless
// enumeration usually runs in. Debian and other distros' native chromium
// packages are real binaries, so they're tried as a fallback for whenever
// the direct download isn't reachable (e.g. an egress-restricted network).
func installChromeLinux() error {
	type strategy struct {
		desc string
		run  func() error
	}
	var strategies []strategy

	if _, err := exec.LookPath("apt-get"); err == nil {
		strategies = append(strategies,
			strategy{"Google Chrome's official .deb (dl.google.com)", installChromeDebFromGoogle},
			strategy{"apt-get install chromium", func() error {
				return runAll([]string{"apt-get", "update"}, []string{"apt-get", "install", "-y", "chromium"})
			}},
		)
	}
	if _, err := exec.LookPath("dnf"); err == nil {
		strategies = append(strategies, strategy{"dnf install chromium", func() error {
			return runCmd("dnf", "install", "-y", "chromium")
		}})
	}
	if _, err := exec.LookPath("yum"); err == nil {
		strategies = append(strategies, strategy{"yum install chromium", func() error {
			return runCmd("yum", "install", "-y", "chromium")
		}})
	}
	if _, err := exec.LookPath("pacman"); err == nil {
		strategies = append(strategies, strategy{"pacman -S chromium", func() error {
			return runCmd("pacman", "-Sy", "--noconfirm", "chromium")
		}})
	}
	if _, err := exec.LookPath("apk"); err == nil {
		strategies = append(strategies, strategy{"apk add chromium", func() error {
			return runCmd("apk", "add", "--no-cache", "chromium")
		}})
	}

	if len(strategies) == 0 {
		return errors.New("no supported package manager found (tried apt-get, dnf, yum, pacman, apk) -- install Chrome/Chromium manually and set -chrome-path")
	}

	var attempted []string
	var errs []string
	for _, s := range strategies {
		attempted = append(attempted, s.desc)
		logify.Infof("headless: Chrome not found, attempting to install it via %s", s.desc)
		if err := s.run(); err != nil {
			errs = append(errs, s.desc+": "+err.Error())
			continue
		}
		if findWorkingChrome() != "" {
			return nil
		}
		errs = append(errs, s.desc+": completed but produced no working browser binary")
	}

	return fmt.Errorf("tried %s but none produced a working browser: %s", strings.Join(attempted, ", "), strings.Join(errs, "; "))
}

// installChromeDebFromGoogle downloads Google Chrome's official .deb
// directly and installs it with apt-get (which resolves its dependencies
// from the system's own repos). This is the same approach most CI configs
// use to get a real, non-snap Chrome onto Debian/Ubuntu.
func installChromeDebFromGoogle() error {
	const debURL = "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb"

	var fetch []string
	switch {
	case commandExists("curl"):
		fetch = []string{"curl", "-fsSL", "-o"}
	case commandExists("wget"):
		fetch = []string{"wget", "-q", "-O"}
	default:
		return errors.New("neither curl nor wget is available to download it")
	}

	debPath := filepath.Join(os.TempDir(), "google-chrome-stable_current_amd64.deb")
	defer os.Remove(debPath)

	args := append(append([]string{}, fetch[1:]...), debPath, debURL)
	if err := runCmd(fetch[0], args...); err != nil {
		return fmt.Errorf("downloading %s: %w", debURL, err)
	}
	if err := runCmd("apt-get", "install", "-y", debPath); err != nil {
		return fmt.Errorf("installing %s: %w", debPath, err)
	}
	return nil
}

// installChromeDarwin installs Chrome via Homebrew, the de facto standard
// package manager on macOS.
func installChromeDarwin() error {
	if !commandExists("brew") {
		return errors.New("Homebrew not found -- install Chrome manually (https://www.google.com/chrome/) or install Homebrew, then retry")
	}
	logify.Infof("headless: Chrome not found, attempting to install it via Homebrew")
	return runCmd("brew", "install", "--cask", "google-chrome")
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// runCmd runs name with args to completion, non-interactively, and turns a
// failure into an error that includes the command's own output -- package
// managers put the actually useful diagnostic (missing dependency, network
// failure, disk full, ...) there, not in the exit code alone.
func runCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "DEBIAN_FRONTEND=noninteractive")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w (%s)", strings.Join(append([]string{name}, args...), " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runAll(cmds ...[]string) error {
	for _, c := range cmds {
		if err := runCmd(c[0], c[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// =========================
// 1) Informational URL filter (moved from runner/testRunner)
// =========================
