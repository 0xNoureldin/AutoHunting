package main

import (
	"net/http"
	"net/http/httptest"
	"sort"
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

func TestHostReturnsForbiddenHTTPFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := &http.Client{Timeout: forbiddenTestTimeoutSeconds * time.Second}
	if !hostReturnsForbidden(client, srv.Listener.Addr().String()) {
		t.Error("expected hostReturnsForbidden to fall back to HTTP and find the 403")
	}
}

func TestHostReturnsForbiddenViaTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	client := srv.Client()
	client.Timeout = forbiddenTestTimeoutSeconds * time.Second
	if !hostReturnsForbidden(client, srv.Listener.Addr().String()) {
		t.Error("expected hostReturnsForbidden to find the 403 over HTTPS")
	}
}
