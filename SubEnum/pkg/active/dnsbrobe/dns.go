package dnsprobe

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/cyinnove/logify"
	"github.com/cyinnove/tldify"
	"github.com/miekg/dns"

	"subenum/pkg/client"
)

type ProbeResult struct {
	Host    string
	Results []*client.Result
}

// Fast Strategy

func runDnsProbe(timeout int, host string) *ProbeResult {
	results := []*client.Result{}

	wildCardType, ok := detectWildcard(host)
	var wildcardHash string
	if ok && wildCardType != nil {
		wildcardHash = getHashForResults(wildCardType)
	}

	// client.Query only errors on a genuine network/transport failure
	// (timeout, connection refused, ...) -- a clean "doesn't exist" comes
	// back as err == nil with an NXDOMAIN/empty-answer status, so this
	// never fires for the ordinary case of most brute-force candidates
	// simply not existing. Track it per-host rather than per-resolver
	// attempt: one flaky resolver among several shouldn't be reported as
	// if the whole probe failed.
	var queryErr error
	resolved := false

resolversLabel:
	for _, r := range client.DefaultResolvers {
		foundAny := false
		result, err := client.Query(host, timeout, dns.TypeA, r)
		if err != nil {
			queryErr = err
			continue
		}
		resolved = true
		if result == nil {
			continue
		}

		if result.DNStatus != "NOERROR" || len(result.Values) == 0 {
			continue
		}

		if !ok {
			results = append(results, result)
			foundAny = true
		} else if getHashForResults(result) != wildcardHash {
			results = append(results, result)
			foundAny = true
		}
		if foundAny {
			break resolversLabel
		}
	}

	if !resolved && queryErr != nil {
		logify.Errorf("DNS probe for %s: every resolver failed, last error: %v", host, queryErr)
	}

	return &ProbeResult{
		Host:    host,
		Results: results,
	}
}

// ProbeSubdomains concurrently probes a list of subdomains and returns only the alive ones
func ProbeSubdomains(subdomains []string, timeout int, concurrency int) []string {
	if len(subdomains) == 0 {
		return []string{}
	}

	// Create a channel to limit concurrency
	semaphore := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex
	aliveSubdomains := []string{}

	// ProbeSubdomains is shared by both the alterx permutation feature and
	// wordlist DNS brute-force, so "candidate(s)" is used here rather than
	// "mutation(s)" -- only the former caller actually mutates anything.
	logify.Infof("Probing %d candidate(s) with concurrency %d", len(subdomains), concurrency)

	// Process subdomains concurrently
	for _, subdomain := range subdomains {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()

			// Acquire semaphore
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// Probe the subdomain
			result := runDnsProbe(timeout, host)

			// If subdomain has valid DNS records, it's alive
			if len(result.Results) > 0 {
				logify.Infof("Discovered alive subdomain: %s", host)
				mu.Lock()
				aliveSubdomains = append(aliveSubdomains, host)
				mu.Unlock()
			}
		}(subdomain)
	}

	// Wait for all goroutines to complete
	wg.Wait()

	logify.Infof("DNS probing completed: %d/%d alive", len(aliveSubdomains), len(subdomains))

	return aliveSubdomains
}

func detectWildcard(host string) (*client.Result, bool) {
	randomSub := time.Now().String()

	parsedDomain, err := tldify.Parse(host)
	if err != nil {
		return nil, false
	}

	fullDomain := fmt.Sprintf("%s.%s.%s", randomSub, parsedDomain.Domain, parsedDomain.TLD)

	res, err := client.Query(fullDomain, 10, dns.TypeA, randomResolver())
	if err != nil {
		return nil, false
	}

	if res != nil && res.DNStatus == "NOERROR" && len(res.Values) > 0 {
		return res, true
	}

	return nil, false
}

func randomResolver() string {
	return client.DefaultResolvers[rand.Intn(len(client.DefaultResolvers))]
}

func getHashForResults(result *client.Result) string {
	if result == nil {
		return ""
	}
	hash := sha256.New()
	hash.Write([]byte(result.RecordName))
	hash.Write([]byte(strings.Join(result.Values, ",")))

	return hex.EncodeToString(hash.Sum(nil))
}
