package main

import (
	"crypto/tls"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// forbiddenProbeTimeoutCapSeconds caps the per-request timeout for the
// direct-subdomain 403 probe, decoupled from the general pipeline
// -timeout (which -active/-fuzz-subs/-fuzz-urls/-vhost can bump to 300s
// as a per-target *budget*). This is a per-request timeout against a
// simple GET, not a budget, so inheriting 300s would let one
// unreachable subdomain block a worker for five minutes.
const forbiddenProbeTimeoutCapSeconds = 10

// forbiddenProbeConcurrencyCap is deliberately generous: unlike vhost
// fuzzing (many requests hammering the *same* target) or port scanning
// (many ports on the same host), every request here goes to a different,
// independent subdomain, so there's no single target to overwhelm.
const forbiddenProbeConcurrencyCap = 50

// probeSubdomainsForForbidden directly requests every subdomain (trying
// HTTPS then HTTP on its own standard ports) and returns the ones whose
// response is 403 Forbidden. Unlike vhost's Host-header fuzzing -- which
// tests wordlist GUESSES against an unknown routing target and must diff
// against a live baseline to rule out "everyone gets the same response
// because none of these hosts are real" -- every entry passed in here is
// already a confirmed, real subdomain (from passive sources, DNS
// brute-force, or vhost discovery merged in earlier), so a 403 on any one
// of them is meaningful on its own: no baseline needed.
func probeSubdomainsForForbidden(subdomains []string, concurrency, timeoutSeconds int) []string {
	if concurrency <= 0 || concurrency > forbiddenProbeConcurrencyCap {
		concurrency = forbiddenProbeConcurrencyCap
	}
	timeout := time.Duration(timeoutSeconds) * time.Second
	if timeoutSeconds <= 0 || timeoutSeconds > forbiddenProbeTimeoutCapSeconds {
		timeout = forbiddenProbeTimeoutCapSeconds * time.Second
	}

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		CheckRedirect: sameHostRedirectPolicy,
	}

	seen := make(map[string]struct{}, len(subdomains))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var forbidden []string

	for _, sub := range subdomains {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		if _, ok := seen[sub]; ok {
			continue
		}
		seen[sub] = struct{}{}

		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer func() { <-sem; wg.Done() }()
			if hostReturnsForbidden(client, host) {
				mu.Lock()
				forbidden = append(forbidden, host)
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
	return forbidden
}

// sameHostRedirectPolicy follows a redirect that stays on the same host
// (e.g. the common http -> https upgrade) but stops at one that jumps to
// a different host: that response belongs to the other host, not the
// subdomain being probed, so reporting its status would misattribute it.
func sameHostRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= 5 {
		return http.ErrUseLastResponse
	}
	if req.URL.Hostname() != via[0].URL.Hostname() {
		return http.ErrUseLastResponse
	}
	return nil
}

// hostReturnsForbidden tries HTTPS then HTTP against host's own standard
// ports and reports whether either responded 403 Forbidden.
func hostReturnsForbidden(client *http.Client, host string) bool {
	for _, scheme := range [...]string{"https", "http"} {
		req, err := http.NewRequest(http.MethodGet, scheme+"://"+host+"/", nil)
		if err != nil {
			continue
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		status := resp.StatusCode
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if status == http.StatusForbidden {
			return true
		}
	}
	return false
}
