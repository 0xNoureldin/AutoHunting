package headless

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestIsChromeNotFoundDetectsForkExecENOENT is a regression test for the
// reported failure -- "[ERR] headless failed for https://...: fork/exec
// /usr/bin/google-chrome: no such file or directory" -- which needs to be
// reliably recognized so Enumerate knows to attempt an install rather than
// just giving up (or, just as importantly, so a genuine navigation
// failure -- DNS, timeout, TLS -- is never mistaken for a missing binary
// and sent through a pointless install attempt).
func TestIsChromeNotFoundDetectsForkExecENOENT(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "definitely-not-a-real-binary")
	cmd := exec.Command(missing)
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected exec of a nonexistent absolute path to fail")
	}
	if !isChromeNotFound(err) {
		t.Errorf("isChromeNotFound(%v) = false, want true (this is exactly the fork/exec ENOENT shape the reported bug hit)", err)
	}
}

func TestIsChromeNotFoundIgnoresUnrelatedErrors(t *testing.T) {
	for _, err := range []error{
		errors.New("net/http: TLS handshake timeout"),
		errors.New("context deadline exceeded"),
		errors.New("dial tcp: lookup nonexistent.example: no such host"),
		nil,
	} {
		if isChromeNotFound(err) {
			t.Errorf("isChromeNotFound(%v) = true, want false -- installing a browser can't fix this and retrying would just waste time", err)
		}
	}
}

func TestFindExistingChromeUsesPath(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "chromium")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("writing fake chromium binary: %v", err)
	}
	t.Setenv("PATH", dir)

	got := findExistingChrome()
	if got != fake {
		t.Errorf("findExistingChrome() = %q, want %q", got, fake)
	}
}

func TestFindExistingChromeReturnsEmptyWhenAbsent(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if got := findExistingChrome(); got != "" {
		t.Errorf("findExistingChrome() = %q, want \"\" (nothing on PATH)", got)
	}
}

// TestFindWorkingChromeSkipsBrokenBinary is a regression test for a real
// failure mode hit while developing this fix: on Ubuntu (in a container,
// the common case for this tool), "apt-get install chromium" installs a
// transitional package that just wraps "snap install chromium". Without a
// working snapd, the resulting /usr/bin/chromium-browser is a real,
// executable file that unconditionally exits non-zero with "requires the
// chromium snap to be installed" the moment it's run. A PATH-only check
// would call that "Chrome is available" and hand back a binary that can't
// actually launch -- so findWorkingChrome must skip it.
func TestFindWorkingChromeSkipsBrokenBinary(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "chromium-browser")
	if err := os.WriteFile(broken, []byte("#!/bin/sh\necho 'requires the chromium snap to be installed' >&2\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("writing broken chromium-browser stub: %v", err)
	}
	t.Setenv("PATH", dir)

	if got := findWorkingChrome(); got != "" {
		t.Errorf("findWorkingChrome() = %q, want \"\" (the only candidate on PATH doesn't actually run)", got)
	}
}

// TestFindWorkingChromeSkipsPastABrokenCandidate proves the search doesn't
// stop at the first name match in commonChromeBinaryNames: if an earlier
// name (e.g. google-chrome, a leftover broken symlink) doesn't run, a
// later one that does must still be found.
func TestFindWorkingChromeSkipsPastABrokenCandidate(t *testing.T) {
	dir := t.TempDir()
	broken := filepath.Join(dir, "google-chrome") // earlier in commonChromeBinaryNames
	working := filepath.Join(dir, "chromium")     // later in commonChromeBinaryNames
	if err := os.WriteFile(broken, []byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatalf("writing broken stub: %v", err)
	}
	if err := os.WriteFile(working, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("writing working stub: %v", err)
	}
	t.Setenv("PATH", dir)

	got := findWorkingChrome()
	if got != working {
		t.Errorf("findWorkingChrome() = %q, want %q (should skip the broken google-chrome and find the working chromium)", got, working)
	}
}

// TestEnsureChromeAvailableFindsExistingBinaryWithoutInstalling is the one
// test in this package allowed to exercise ensureChromeAvailable's
// sync.Once-guarded body (it runs at most once per process by design, so
// only one test can meaningfully drive it). With a fake "chromium" on
// PATH, it must resolve via findExistingChrome and never fall through to
// an actual package-manager install.
func TestEnsureChromeAvailableFindsExistingBinaryWithoutInstalling(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, "chromium")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("writing fake chromium binary: %v", err)
	}
	t.Setenv("PATH", dir)

	got, err := ensureChromeAvailable()
	if err != nil {
		t.Fatalf("ensureChromeAvailable() error = %v, want nil", err)
	}
	if got != fake {
		t.Errorf("ensureChromeAvailable() = %q, want %q", got, fake)
	}
}
