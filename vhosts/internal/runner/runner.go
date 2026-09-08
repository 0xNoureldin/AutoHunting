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

						// Detect vhost: compare response to baseline
						if !baseline.inRange(vhostResp) {
							mu.Lock()
							resultMap[ipAddr] = append(resultMap[ipAddr], h)
							mu.Unlock()
						}
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

// baselineRange is the range of "not actually a distinct vhost" responses
// observed across several baseline samples. A single sample is fragile: any
// natural variance between requests (a server that echoes the Host header
// into an error page, cache/CDN timing, etc.) would make every candidate
// look like a hit. Ranging over several samples absorbs that noise.
type baselineRange struct {
	statusMin, statusMax int
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
	if resp.StatusCode < r.statusMin || resp.StatusCode > r.statusMax {
		return false
	}
	if resp.ContentLength < r.lengthMin-lengthTolerance || resp.ContentLength > r.lengthMax+lengthTolerance {
		return false
	}
	return true
}

// captureBaselineRange requests validURL 3 times with a random, practically
// guaranteed-absent Host header and returns the range of responses seen.
// Each invalid host is the same fixed length (a 16-char hex token) so that a
// server echoing the Host header into its response body doesn't itself
// introduce content-length variance unrelated to real vhost differences.
func captureBaselineRange(timeout int, validURL string) (baselineRange, error) {
	const samples = 3
	var resps []*http.Response

	for i := 0; i < samples; i++ {
		token, err := randomToken()
		if err != nil {
			return baselineRange{}, err
		}
		resp, err := http.GetResponse(timeout, token+"-invalid.invalid", validURL)
		if err != nil || resp == nil {
			return baselineRange{}, fmt.Errorf("baseline request failed: %w", err)
		}
		resps = append(resps, resp)
	}

	r := baselineRange{
		statusMin: resps[0].StatusCode, statusMax: resps[0].StatusCode,
		lengthMin: resps[0].ContentLength, lengthMax: resps[0].ContentLength,
	}
	for _, resp := range resps[1:] {
		if resp.StatusCode < r.statusMin {
			r.statusMin = resp.StatusCode
		}
		if resp.StatusCode > r.statusMax {
			r.statusMax = resp.StatusCode
		}
		if resp.ContentLength < r.lengthMin {
			r.lengthMin = resp.ContentLength
		}
		if resp.ContentLength > r.lengthMax {
			r.lengthMax = resp.ContentLength
		}
	}
	return r, nil
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
