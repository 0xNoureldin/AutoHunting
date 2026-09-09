package runner

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/cyinnove/logify"

	"github.com/zomaxsec/vhoster/pkg/dns"
	"github.com/zomaxsec/vhoster/pkg/http"
	"github.com/zomaxsec/vhoster/pkg/utils"
)

func Run(opts *Options) error {

	if opts.HostsFile != "" {
		var err error
		opts.Hosts, err = utils.ReadLines(opts.HostsFile)
		if err != nil {
			return err
		}

	}

	if opts.IPsFile != "" {
		var err error
		opts.IPs, err = utils.ReadLines(opts.IPsFile)
		if err != nil {
			return err
		}
		opts.skipDNSResolve = true
	}

	// map[IP][]Hosts - protected by mutex for concurrent access
	resultMap := map[string][]string{}
	var mu sync.Mutex

	// Create semaphore for concurrency control
	concurrency := opts.Concurrency
	if concurrency <= 0 {
		concurrency = 10 // Default concurrency
	}
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	if !opts.skipDNSResolve {
		// Concurrent DNS resolution
		for _, host := range opts.Hosts {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(h string) {
				defer func() {
					<-sem // Release semaphore
					wg.Done()
				}()

				ips, err := dns.ProbeHost(h, opts.Timeout, opts.MaxTries)
				if err != nil {
					return
				}

				// Thread-safe append to resultMap
				mu.Lock()
				for _, ip := range ips {
					resultMap[ip] = append(resultMap[ip], h)
				}
				mu.Unlock()
			}(host)
		}

		wg.Wait()

	} else {
		// Concurrent vhost enumeration
		for _, ip := range opts.IPs {
			wg.Add(1)
			sem <- struct{}{} // Acquire semaphore

			go func(ipAddr string) {
				defer func() {
					<-sem // Release semaphore
					wg.Done()
				}()

				// Generate valid HTTP URL for this IP
				validURL := http.ProbeHTTP(ipAddr, opts.Timeout)
				if validURL == "" {
					return
				}

				baseline, err := captureBaselineRange(opts.Timeout, validURL)
				if err != nil {
					return
				}

				// Fuzz Host headers with actual domains (concurrent per IP)
				var hostWg sync.WaitGroup
				hostSem := make(chan struct{}, concurrency)

				for _, host := range opts.Hosts {
					hostWg.Add(1)
					hostSem <- struct{}{}

					go func(h string) {
						defer func() {
							<-hostSem
							hostWg.Done()
						}()

						// Send request with Host header set to the domain
						vhostResp, err := http.GetResponse(opts.Timeout, h, validURL)
						if err != nil {
							return
						}

						if baseline.inRange(vhostResp) {
							return
						}

						// vhostResp differs from the baseline captured once at the
						// start of the scan. Before reporting a hit, confirm it
						// against a *fresh* control probe -- a brand new random,
						// guaranteed-absent host -- taken right now. Sending
						// thousands of rapid Host-header requests at one server
						// can itself trip a WAF/anti-bot challenge or rate limit
						// partway through a scan; once that happens, EVERY
						// remaining response (real or fake host alike) starts
						// looking different from the now-stale starting baseline,
						// which is exactly what turns an entire wordlist into
						// "hits". If an unknown host looks just as different
						// right now as our candidate does, the difference is
						// environmental drift, not a real vhost -- and if the
						// control probe itself fails, we can't rule that out, so
						// we don't report a hit either.
						control, err := probeControl(opts.Timeout, validURL)
						if err != nil || sameEnvelope(vhostResp, control) {
							return
						}

						mu.Lock()
						resultMap[ipAddr] = append(resultMap[ipAddr], h)
						mu.Unlock()
					}(host)
				}

				hostWg.Wait()
			}(ip)
		}

		wg.Wait()
	}

	// Output results
	if err := outputResults(resultMap, opts); err != nil {
		return err
	}

	return nil
}

// baselineRange is the envelope of "not actually a distinct vhost"
// responses observed across several baseline samples. A single sample is
// fragile: any natural variance between requests (a server that echoes the
// Host header into an error page, cache/CDN timing, etc.) would make every
// candidate look like a hit. Ranging over several samples absorbs that
// noise.
//
// Status codes are categorical, not ordinal, so they're tracked as the set
// actually observed rather than a min-max range -- a baseline that saw 200
// on one sample and 404 on another must not treat every code in between
// (301, 302, ...) as "normal", which a numeric range would.
type baselineRange struct {
	statuses             map[int]struct{}
	lengthMin, lengthMax int64
}

// lengthTolerance absorbs modest, non-vhost-related content-length variance
// -- notably a server that echoes the (varying-length) Host header into an
// otherwise-static error page, which would otherwise make every candidate
// look distinct purely because its hostname is a different length than the
// baseline probe's. A genuinely different vhost is expected to differ by
// far more than this (a different page entirely), so this is deliberately
// small relative to that.
const lengthTolerance = 64

func (r baselineRange) inRange(resp *http.Response) bool {
	if _, ok := r.statuses[resp.StatusCode]; !ok {
		return false
	}
	if resp.ContentLength < r.lengthMin-lengthTolerance || resp.ContentLength > r.lengthMax+lengthTolerance {
		return false
	}
	return true
}

// sameEnvelope reports whether two responses look like the same kind of
// "unrecognized host" response: an identical status code, and content
// lengths within lengthTolerance of each other. Unlike inRange, this
// compares two live responses captured back-to-back rather than a response
// against a baseline captured earlier -- see probeControl's use in Run.
func sameEnvelope(a, b *http.Response) bool {
	if a.StatusCode != b.StatusCode {
		return false
	}
	diff := a.ContentLength - b.ContentLength
	if diff < 0 {
		diff = -diff
	}
	return diff <= lengthTolerance
}

// captureBaselineRange requests validURL 3 times with a random, practically
// guaranteed-absent Host header and returns the range of responses seen.
func captureBaselineRange(timeout int, validURL string) (baselineRange, error) {
	const samples = 3
	var resps []*http.Response

	for i := 0; i < samples; i++ {
		resp, err := probeControl(timeout, validURL)
		if err != nil {
			return baselineRange{}, fmt.Errorf("baseline request failed: %w", err)
		}
		resps = append(resps, resp)
	}

	r := baselineRange{
		statuses:  map[int]struct{}{},
		lengthMin: resps[0].ContentLength,
		lengthMax: resps[0].ContentLength,
	}
	for _, resp := range resps {
		r.statuses[resp.StatusCode] = struct{}{}
		if resp.ContentLength < r.lengthMin {
			r.lengthMin = resp.ContentLength
		}
		if resp.ContentLength > r.lengthMax {
			r.lengthMax = resp.ContentLength
		}
	}
	return r, nil
}

// probeControl requests validURL with a fresh, random, practically
// guaranteed-absent Host header and returns the response. It's used both to
// build the initial baseline (captureBaselineRange) and, per candidate, as
// a live "what does an unknown host look like right now" control -- see
// sameEnvelope and its use in Run. Each invalid host is the same fixed
// length (a 16-char hex token) so that a server echoing the Host header
// into its response body doesn't itself introduce content-length variance
// unrelated to real vhost differences.
func probeControl(timeout int, validURL string) (*http.Response, error) {
	token, err := randomToken()
	if err != nil {
		return nil, err
	}
	resp, err := http.GetResponse(timeout, token+"-invalid.invalid", validURL)
	if err != nil || resp == nil {
		return nil, fmt.Errorf("control request failed: %w", err)
	}
	return resp, nil
}

func randomToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// outputResults handles outputting results in JSON format to file and CLI format to console
func outputResults(resultMap map[string][]string, opts *Options) error {
	// Write JSON output to file
	if opts.OutputFile != "" {
		jsonData, err := json.MarshalIndent(resultMap, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		outputFile := opts.OutputFile
		if !strings.HasSuffix(outputFile, ".json") {
			outputFile += ".json"
		}

		if err := os.WriteFile(outputFile, jsonData, os.ModePerm); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
	}

	if !opts.Silent {
		printCLIResults(resultMap)
	}

	return nil
}

func printCLIResults(resultMap map[string][]string) {
	if len(resultMap) == 0 {
		fmt.Println("No results found.")
		return
	}

	for ip, hosts := range resultMap {
		if len(hosts) > 0 {
			logify.Infof("%s", ip)
			for _, host := range hosts {
				fmt.Printf("  - %s\n", host)
			}
			fmt.Println()
		}
	}
}
