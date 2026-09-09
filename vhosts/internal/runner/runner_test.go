package runner

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	vhttp "github.com/zomaxsec/vhoster/pkg/http"
)

// TestCaptureBaselineRangeThenInRange is a regression test for the false
// positive this package used to produce: a single-sample, exact-match
// baseline flagged every candidate as a distinct vhost, including ones that
// don't exist, because a server can legitimately return slightly different
// responses across requests (timing, an echoed Host header, etc.) even when
// nothing is actually routed differently. Ranging over several samples
// should absorb that and only flag hosts the server truly treats
// differently.
func TestCaptureBaselineRangeThenInRange(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Host {
		case "admin.example.test":
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin panel - distinctly different and longer body than the default vhost"))
		case "redirect.example.test":
			w.WriteHeader(http.StatusFound)
		default:
			// The common real-world case: a fixed, static error page for
			// any host the server doesn't recognize (e.g. nginx's default
			// vhost), not echoing the Host header back.
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<html><body><h1>404 Not Found</h1></body></html>"))
		}
	}))
	defer srv.Close()

	baseline, err := captureBaselineRange(5, srv.URL)
	if err != nil {
		t.Fatalf("captureBaselineRange: %v", err)
	}

	get := func(host string) *vhttp.Response {
		t.Helper()
		resp, err := vhttp.GetResponse(5, host, srv.URL)
		if err != nil {
			t.Fatalf("GetResponse(%q): %v", host, err)
		}
		return resp
	}

	// Real vhosts: must be reported as OUTSIDE the baseline range.
	if baseline.inRange(get("admin.example.test")) {
		t.Error("admin.example.test: expected to be flagged as a distinct vhost, but it matched the baseline range")
	}
	if baseline.inRange(get("redirect.example.test")) {
		t.Error("redirect.example.test: expected to be flagged as a distinct vhost, but it matched the baseline range")
	}

	// Non-existent candidates, including ones whose Host header length
	// differs from the baseline probes' -- must stay INSIDE the range
	// (i.e. not falsely flagged as vhosts).
	for _, host := range []string{
		"doesnotexist.example.test",
		"a.example.test",
		"this-is-a-much-longer-fake-subdomain-name.example.test",
	} {
		if !baseline.inRange(get(host)) {
			t.Errorf("%s: false positive -- flagged as a distinct vhost but it isn't one", host)
		}
	}
}

// TestInRangeToleratesHostEchoingErrorPage covers a harder, less common
// case: a server that echoes the (varying-length) Host header into an
// otherwise-static error page, which makes Content-Length a function of the
// candidate's hostname length even with no real vhost routing involved.
// lengthTolerance is what keeps ordinary-length wordlist candidates from
// being misread as distinct vhosts here; a genuinely different vhost still
// has to differ by far more than that to register.
func TestInRangeToleratesHostEchoingErrorPage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "admin.example.test" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin panel - a completely different page, not related to the error template at all"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("no such vhost: " + r.Host))
	}))
	defer srv.Close()

	baseline, err := captureBaselineRange(5, srv.URL)
	if err != nil {
		t.Fatalf("captureBaselineRange: %v", err)
	}

	get := func(host string) *vhttp.Response {
		t.Helper()
		resp, err := vhttp.GetResponse(5, host, srv.URL)
		if err != nil {
			t.Fatalf("GetResponse(%q): %v", host, err)
		}
		return resp
	}

	if baseline.inRange(get("admin.example.test")) {
		t.Error("admin.example.test: expected to be flagged as a distinct vhost, but it matched the baseline range")
	}
	for _, host := range []string{"www.example.test", "api.example.test", "staging.example.test"} {
		if !baseline.inRange(get(host)) {
			t.Errorf("%s: false positive against a host-echoing error page (ordinary-length candidate)", host)
		}
	}
}

// TestRunSurvivesMidScanDrift is a regression test for the false-positive
// report where a 5000-word wordlist produced 5000 "discovered vhosts" --
// literally every candidate flagged as a hit. That happens when something
// about the target's responses changes partway through the scan (a WAF or
// anti-bot defense kicking in after enough rapid requests, rate limiting,
// etc.): the baseline was captured once at the very start, so once the
// target's behavior drifts, EVERY remaining response -- real host or fake
// -- looks different from that now-stale baseline. Run must confirm each
// apparent hit against a live control probe taken at that same moment
// rather than trusting the original baseline forever.
func TestRunSurvivesMidScanDrift(t *testing.T) {
	var requestCount int32
	const driftAfter = 20

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := atomic.AddInt32(&requestCount, 1)

		if r.Host == "real-admin.example.test" {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("admin panel - a genuinely different vhost, present throughout the scan"))
			return
		}

		if n <= driftAfter {
			// Normal behavior at the start of the scan (covers the
			// baseline capture and the first few candidates).
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte("<html><body><h1>404 Not Found</h1></body></html>"))
			return
		}

		// Simulated drift: from here on, EVERY unrecognized host (and,
		// in a real WAF, arguably every host at all) gets a challenge
		// page with a random per-request token, unrelated to vhost
		// routing entirely.
		token, _ := randomToken()
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html><body>Access denied - ray-id " + token + "</body></html>"))
	}))
	defer srv.Close()

	hosts := []string{"real-admin.example.test"}
	for i := 0; i < 200; i++ {
		hosts = append(hosts, fmt.Sprintf("fake-word-%d.example.test", i))
	}

	// http.ProbeHTTP only tries a fixed list of ports and won't find this
	// ephemeral-port test server, so this exercises the same detection
	// logic Run's per-candidate loop uses (captureBaselineRange, then
	// inRange + the probeControl/sameEnvelope confirmation) directly
	// against srv.URL, rather than going through Run/ProbeHTTP.
	const timeout = 5
	baseline, err := captureBaselineRange(timeout, srv.URL)
	if err != nil {
		t.Fatalf("captureBaselineRange: %v", err)
	}

	var hits []string
	for _, h := range hosts {
		resp, err := vhttp.GetResponse(timeout, h, srv.URL)
		if err != nil {
			t.Fatalf("GetResponse(%q): %v", h, err)
		}
		if baseline.inRange(resp) {
			continue
		}
		control, err := probeControl(timeout, srv.URL)
		if err != nil || sameEnvelope(resp, control) {
			continue
		}
		hits = append(hits, h)
	}

	if len(hits) != 1 || hits[0] != "real-admin.example.test" {
		t.Fatalf("expected only real-admin.example.test to be flagged once drift kicks in, got %v (out of %d candidates)", hits, len(hosts))
	}
}

// TestForbiddenResponsesRecordedRegardlessOfHitStatus covers a host that's
// real but access-gated (an internal admin panel, an IP-allowlisted
// endpoint) and so returns the exact same 403 page as every unrecognized
// Host too. Baseline-diffing correctly does NOT flag it as a distinct
// vhost -- but a 403 is worth a human's attention regardless, so it must
// still turn up in the separate 403 list Run produces (see forbiddenMap).
func TestForbiddenResponsesRecordedRegardlessOfHitStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html><body>403 Forbidden</body></html>"))
	}))
	defer srv.Close()

	const timeout = 5
	baseline, err := captureBaselineRange(timeout, srv.URL)
	if err != nil {
		t.Fatalf("captureBaselineRange: %v", err)
	}

	hosts := []string{"gated.example.test", "also-gated.example.test"}
	var forbidden []string
	for _, h := range hosts {
		resp, err := vhttp.GetResponse(timeout, h, srv.URL)
		if err != nil {
			t.Fatalf("GetResponse(%q): %v", h, err)
		}
		if resp.StatusCode == httpStatusForbidden {
			forbidden = append(forbidden, h)
		}
		if !baseline.inRange(resp) {
			t.Errorf("%s: expected to match the baseline (same generic 403 page everywhere), so it must NOT also be reported as a distinct vhost hit", h)
		}
	}

	if len(forbidden) != len(hosts) {
		t.Fatalf("expected both hosts to be recorded as 403s regardless of hit status, got %v", forbidden)
	}
}

func TestForbiddenOutputPath(t *testing.T) {
	cases := map[string]string{
		"results":      "results_403.json",
		"results.json": "results_403.json",
	}
	for in, want := range cases {
		if got := forbiddenOutputPath(in); got != want {
			t.Errorf("forbiddenOutputPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestOutputResultsWritesForbiddenFileOnlyWhenNonEmpty(t *testing.T) {
	dir := t.TempDir()
	outputFile := filepath.Join(dir, "results")

	if err := outputResults(map[string][]string{"1.2.3.4": {"real.example.test"}}, nil, &Options{OutputFile: outputFile, Silent: true}); err != nil {
		t.Fatalf("outputResults: %v", err)
	}
	if _, err := os.Stat(outputFile + "_403.json"); !os.IsNotExist(err) {
		t.Errorf("expected no 403 output file when there are no 403s")
	}

	if err := outputResults(map[string][]string{}, map[string][]string{"1.2.3.4": {"gated.example.test"}}, &Options{OutputFile: outputFile, Silent: true}); err != nil {
		t.Fatalf("outputResults: %v", err)
	}
	data, err := os.ReadFile(outputFile + "_403.json")
	if err != nil {
		t.Fatalf("expected 403 output file to be written: %v", err)
	}
	var got map[string][]string
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(got["1.2.3.4"]) != 1 || got["1.2.3.4"][0] != "gated.example.test" {
		t.Errorf("unexpected 403 output contents: %v", got)
	}
}
