package runner

import (
	"net/http"
	"net/http/httptest"
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
