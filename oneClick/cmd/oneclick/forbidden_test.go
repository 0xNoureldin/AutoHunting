package main

import (
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"testing"
	"time"
)

const forbiddenTestTimeoutSeconds = 5

func TestProbeSubdomainsForForbiddenFindsNothingOnOKHandler(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer srv.Close()

	got := probeSubdomainsForForbidden([]string{srv.Listener.Addr().String()}, 5, forbiddenTestTimeoutSeconds)
	if len(got) != 0 {
		t.Errorf("expected no 403s for a 200 OK handler, got %v", got)
	}
}

func TestProbeSubdomainsForForbiddenDedupesInput(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	host := srv.Listener.Addr().String()
	got := probeSubdomainsForForbidden([]string{host, host, host}, 5, forbiddenTestTimeoutSeconds)
	if len(got) != 1 {
		t.Fatalf("expected exactly one result for a duplicated host, got %v", got)
	}
	// The plain-HTTP test server has no TLS listener, so the HTTPS
	// attempt fails immediately (no hit) and only the HTTP GET counts.
	if hits != 1 {
		t.Errorf("expected the server to be hit exactly once (dedup before probing), got %d hits", hits)
	}
}

func TestProbeSubdomainsForForbiddenSkipsBlank(t *testing.T) {
	got := probeSubdomainsForForbidden([]string{"", "  ", ""}, 5, forbiddenTestTimeoutSeconds)
	if len(got) != 0 {
		t.Errorf("expected no results for blank input, got %v", got)
	}
}

func TestProbeSubdomainsForForbiddenMultipleHosts(t *testing.T) {
	gated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer gated.Close()
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer open.Close()
	notFound := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer notFound.Close()

	hosts := []string{
		gated.Listener.Addr().String(),
		open.Listener.Addr().String(),
		notFound.Listener.Addr().String(),
	}
	got := probeSubdomainsForForbidden(hosts, 5, forbiddenTestTimeoutSeconds)
	sort.Strings(got)
	want := []string{gated.Listener.Addr().String()}
	if len(got) != len(want) || got[0] != want[0] {
		t.Errorf("got %v, want %v", got, want)
	}
}

// TestFilterGenericForbiddenSuppressesMajoritySignature is a regression
// test for the reported false-positive flood: thousands of confirmed-real
// subdomains all coming back with an identical 403 (same status, same
// byte count) -- either from a WAF/CDN blocking every request
// indiscriminately, or from unrelated names resolving to the same origin
// upstream (wildcard DNS). filterGenericForbidden must drop the dominant,
// shared signature and keep only genuinely distinct 403s.
func TestFilterGenericForbiddenSuppressesMajoritySignature(t *testing.T) {
	var hits []forbiddenHit
	for i := 0; i < 20; i++ {
		hits = append(hits, forbiddenHit{host: "fake" + strconv.Itoa(i) + ".example.test", length: 4908})
	}
	hits = append(hits, forbiddenHit{host: "gated.example.test", length: 812})

	got := filterGenericForbidden(hits)
	if len(got) != 1 || got[0] != "gated.example.test" {
		t.Errorf("expected only the distinct 403 to survive, got %v", got)
	}
}

// TestFilterGenericForbiddenReportsAllBelowSampleFloor covers the other
// side: too few 403 hits to tell "several genuinely gated hosts happen to
// share a length" apart from "everything's blocked identically" -- below
// forbiddenNoiseMinSamples, nothing is suppressed.
func TestFilterGenericForbiddenReportsAllBelowSampleFloor(t *testing.T) {
	hits := []forbiddenHit{
		{host: "a.example.test", length: 500},
		{host: "b.example.test", length: 500},
		{host: "c.example.test", length: 500},
	}
	got := filterGenericForbidden(hits)
	if len(got) != 3 {
		t.Errorf("expected all 3 hits below the sample floor to be reported, got %v", got)
	}
}

// TestFilterGenericForbiddenNoClearMajority covers a mixed set with no
// single dominant signature: nothing should be suppressed, since there's
// no basis to call any one of them "the generic one".
func TestFilterGenericForbiddenNoClearMajority(t *testing.T) {
	hits := []forbiddenHit{
		{host: "a.example.test", length: 100},
		{host: "b.example.test", length: 200},
		{host: "c.example.test", length: 300},
		{host: "d.example.test", length: 400},
		{host: "e.example.test", length: 500},
	}
	got := filterGenericForbidden(hits)
	if len(got) != 5 {
		t.Errorf("expected all 5 hits to be reported (no majority signature), got %v", got)
	}
}

// TestProbeSubdomainsForForbiddenSuppressesUniformBlock drives the same
// scenario as TestFilterGenericForbiddenSuppressesMajoritySignature
// end-to-end through probeSubdomainsForForbidden, against real local HTTP
// servers: many hosts sharing one WAF-style block page, one host with its
// own genuinely distinct 403.
func TestProbeSubdomainsForForbiddenSuppressesUniformBlock(t *testing.T) {
	const genericBody = "<html><body>403 Forbidden</body></html>"
	genericHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(genericBody))
	})

	var hosts []string
	for i := 0; i < 6; i++ {
		srv := httptest.NewServer(genericHandler)
		t.Cleanup(srv.Close)
		hosts = append(hosts, srv.Listener.Addr().String())
	}

	gated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte("<html><body>Access Denied: insufficient permissions for this internal panel.</body></html>"))
	}))
	t.Cleanup(gated.Close)
	hosts = append(hosts, gated.Listener.Addr().String())

	got := probeSubdomainsForForbidden(hosts, 10, forbiddenTestTimeoutSeconds)
	if len(got) != 1 || got[0] != gated.Listener.Addr().String() {
		t.Errorf("expected only the distinct 403 (%s) to be reported, got %v", gated.Listener.Addr().String(), got)
	}
}

func TestHostForbiddenLengthHTTPFallback(t *testing.T) {
	const body = "forbidden"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(body))
	}))
	defer srv.Close()

	client := &http.Client{Timeout: forbiddenTestTimeoutSeconds * time.Second}
	length, ok := hostForbiddenLength(client, srv.Listener.Addr().String())
	if !ok {
		t.Fatal("expected hostForbiddenLength to fall back to HTTP and find the 403")
	}
	if length != int64(len(body)) {
		t.Errorf("length = %d, want %d", length, len(body))
	}
}

func TestHostForbiddenLengthViaTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := srv.Client()
	client.Timeout = forbiddenTestTimeoutSeconds * time.Second
	if _, ok := hostForbiddenLength(client, srv.Listener.Addr().String()); !ok {
		t.Error("expected hostForbiddenLength to find the 403 over HTTPS")
	}
}
