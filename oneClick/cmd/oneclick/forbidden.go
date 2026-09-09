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
// 403 Forbidden response is genuinely meaningful. Unlike vhost's
// Host-header fuzzing -- which tests wordlist GUESSES against an unknown
// routing target -- every entry passed in here is already a confirmed,
// real subdomain, so in the common case a 403 is meaningful on its own.
// But "confirmed real subdomain" doesn't rule out every host being
// blocked identically for a reason that has nothing to do with any one of
// them individually -- a WAF/CDN 403-ing every request that doesn't look
// like a browser, a global rate limit, or (upstream, in subdomain
// enumeration) a wildcard DNS record that made non-existent names resolve
// in the first place. When that happens, hundreds or thousands of
// "confirmed real" subdomains all come back with the exact same 403 page,
// which carries no more signal than the vhost-fuzzing case the baseline
// there was built for. So the same principle applies here: only report a
// host whose 403 is genuinely distinct from whatever the overwhelming
// majority of other 403s on this run look like -- see
// filterGenericForbidden.
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
	var hits []forbiddenHit

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
			if length, ok := hostForbiddenLength(client, host); ok {
				mu.Lock()
				hits = append(hits, forbiddenHit{host: host, length: length})
				mu.Unlock()
			}
		}(sub)
	}
	wg.Wait()
	return filterGenericForbidden(hits)
}

// forbiddenHit is one host whose probe came back 403 Forbidden, along with
// the response body length used to tell a genuinely distinct 403 apart
// from a generic one every blocked host gets -- see filterGenericForbidden.
type forbiddenHit struct {
	host   string
	length int64
}

// forbiddenNoiseMinSamples is the fewest 403 hits filterGenericForbidden
// requires before it will treat any shared response shape as generic
// noise. Below this there's too little data to tell "several genuinely
// gated hosts happen to run the same software" apart from "everything's
// being blocked identically" -- so everything is reported, as before.
const forbiddenNoiseMinSamples = 5

// forbiddenNoiseMajorityFraction is how much of all collected 403 hits a
// single response-length bucket has to account for before it's treated as
// the generic/blocked-by-default response rather than real, host-specific
// signal.
const forbiddenNoiseMajorityFraction = 0.5

// forbiddenLengthTolerance groups 403 responses whose body length is
// within this many bytes of each other into the same bucket, absorbing
// minor per-request variance (a timestamp, a request ID) in an otherwise
// identical block page -- mirroring vhost's own lengthTolerance.
const forbiddenLengthTolerance = 64

// filterGenericForbidden drops any hit whose response length falls in the
// single bucket that accounts for at least forbiddenNoiseMajorityFraction
// of all hits (once there are at least forbiddenNoiseMinSamples of them):
// that's the signature of a block applied uniformly across hosts -- a
// WAF/CDN's default-deny page, a bot-detection challenge, or upstream
// wildcard DNS having made unrelated names resolve to the same origin --
// rather than a real, host-specific 403 worth a human's attention.
func filterGenericForbidden(hits []forbiddenHit) []string {
	if len(hits) < forbiddenNoiseMinSamples {
		out := make([]string, len(hits))
		for i, h := range hits {
			out[i] = h.host
		}
		return out
	}

	const bucketWidth = forbiddenLengthTolerance + 1
	counts := map[int64]int{}
	bucketOf := func(h forbiddenHit) int64 { return h.length / bucketWidth }
	for _, h := range hits {
		counts[bucketOf(h)]++
	}

	var majorityBucket int64
	majorityCount := 0
	for b, c := range counts {
		if c > majorityCount {
			majorityBucket, majorityCount = b, c
		}
	}
	if float64(majorityCount) < forbiddenNoiseMajorityFraction*float64(len(hits)) {
		out := make([]string, len(hits))
		for i, h := range hits {
			out[i] = h.host
		}
		return out
	}

	var out []string
	for _, h := range hits {
		if bucketOf(h) != majorityBucket {
			out = append(out, h.host)
		}
	}
	return out
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

// hostForbiddenLength tries HTTPS then HTTP against host's own standard
// ports and, if either responded 403 Forbidden, returns the number of
// response body bytes actually read (not the Content-Length header, which
// can be absent or -1 for a chunked response) and ok=true.
func hostForbiddenLength(client *http.Client, host string) (length int64, ok bool) {
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
		n, _ := io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if status == http.StatusForbidden {
			return n, true
		}
	}
	return 0, false
}
