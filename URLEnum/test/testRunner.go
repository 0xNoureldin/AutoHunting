package test

import (
	"context"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/cyinnove/logify"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/active/crawl"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/active/fuzz"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/active/headless"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper/sources"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/utils"
)

func Run(opts *Options) error {
	opts.queries = utils.ExtractDomainsFromString(opts.Domain)
	if opts.Domain == "" && opts.Input == "" {
		logify.Fatalf("No domain or input file specified")
	}

	if opts.Input != "" {
		var err error
		opts.queries, err = utils.ReadInputFromFile(opts.Input)
		if err != nil {
			logify.Errorf("Error reading queries from file %s: %v", opts.Input, err)
			return err
		}
	}

	if len(opts.queries) == 0 {
		logify.Fatalf("No domain specified for enumeration")
	}

	// defaults
	if opts.PassiveConcurrency <= 0 {
		opts.PassiveConcurrency = 5
	}
	if opts.ActiveConcurrency <= 0 {
		opts.ActiveConcurrency = 10
	}

	apiKeys, err := scraper.ExtractALLAPIKeys()
	if err != nil {
		logify.Fatalf("Failed to read config: %v", err)
	}

	// Shared results across all workers (dedupe)
	allResults := make(map[string]string)
	var resultsMu sync.Mutex

	addResult := func(u string) {
		u = strings.TrimSpace(u)
		if u == "" {
			return
		}
		if !utils.IsInformationalURL(u) {
			return
		}

		key := dedupKey(u)
		if key == "" {
			return
		}

		rep := canonicalURL(u)
		if rep == "" {
			rep = u
		}

		resultsMu.Lock()
		if _, exists := allResults[key]; !exists {
			// first wins
			allResults[key] = rep
		}
		resultsMu.Unlock()
	}

	// =========================
	// Concurrency split (ONLY LOGIC CHANGE)
	// =========================
	p := opts.PassiveConcurrency
	a := opts.ActiveConcurrency

	// Passive: split between webarchive and commoncrawl
	webWorkers := max(1, p/2)
	ccWorkers := max(1, p-webWorkers)

	// Active: split between crawl and headless
	crawlWorkers := max(1, a/2)
	headlessWorkers := max(1, a-crawlWorkers)

	logify.Infof("Worker split => webarchive=%d, commoncrawl=%d, crawl=%d, headless=%d",
		webWorkers, ccWorkers, crawlWorkers, headlessWorkers,
	)

	// =========================
	// Passive Enumeration (same flow: queries -> sources)
	// BUT: workers are distributed across 2 passive sources
	// =========================

	srcs := sources.GetAllSources(apiKeys)

	// pick the two passive sources
	var webSrc scraper.Source
	var ccSrc scraper.Source
	for _, s := range srcs {
		switch strings.ToLower(strings.TrimSpace(s.Name())) {
		case "webarchive":
			webSrc = s
		case "commoncrawl":
			ccSrc = s
		}
	}

	// broadcast queries to both passive pipelines
	webJobs := make(chan string, len(opts.queries))
	ccJobs := make(chan string, len(opts.queries))

	for _, q := range opts.queries {
		q = strings.TrimSpace(q)
		if q == "" || strings.HasPrefix(q, "#") {
			continue
		}
		webJobs <- q
		ccJobs <- q
	}
	close(webJobs)
	close(ccJobs)

	var wg sync.WaitGroup

	// --- webarchive workers ---
	if webSrc != nil {
		for i := 0; i < webWorkers; i++ {
			wg.Add(1)
			workerID := i + 1
			go func(id int) {
				defer wg.Done()
				client := scraper.NewSession(opts.Timeout)

				for q := range webJobs {
					logify.Infof("[WEB-W%02d] Starting enumeration for domain: %s via webarchive", id, q)

					ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
					urls, err := webSrc.Search(ctx, q, client)
					cancel()

					if err != nil {
						logify.Errorf("[WEB-W%02d] webarchive failed for %s: %v", id, q, err)
					} else {
						for _, u := range urls {
							addResult(u)
						}
					}

					resultsMu.Lock()
					total := len(allResults)
					resultsMu.Unlock()
					logify.Infof("[WEB-W%02d] Done %s. Total unique URLs so far: %d", id, q, total)

					time.Sleep(10 * time.Second)
				}
			}(workerID)
		}
	} else {
		logify.Errorf("webarchive source not found; skipping webarchive workers")
	}

	// --- commoncrawl workers ---
	if ccSrc != nil {
		for i := 0; i < ccWorkers; i++ {
			wg.Add(1)
			workerID := i + 1
			go func(id int) {
				defer wg.Done()
				client := scraper.NewSession(opts.Timeout)

				for q := range ccJobs {
					logify.Infof("[CC-W%02d] Starting enumeration for domain: %s via commoncrawl", id, q)

					ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
					urls, err := ccSrc.Search(ctx, q, client)
					cancel()

					if err != nil {
						// keep your old behavior: skip CC errors quietly
						continue
					}
					for _, u := range urls {
						addResult(u)
					}

					resultsMu.Lock()
					total := len(allResults)
					resultsMu.Unlock()
					logify.Infof("[CC-W%02d] Done %s. Total unique URLs so far: %d", id, q, total)

					time.Sleep(10 * time.Second)
				}
			}(workerID)
		}
	} else {
		logify.Errorf("commoncrawl source not found; skipping commoncrawl workers")
	}

	wg.Wait()

	// Collect unique URLs after passive stage
	uniqueURLs := make([]string, 0, len(allResults))
	for _, u := range allResults {
		uniqueURLs = append(uniqueURLs, u)
	}

	// =========================
	// Active Enumeration (crawl, then headless) -- gated on -active.
	// Fuzzing (wordlist-based path/content discovery) -- gated on
	// -w/-wordlist, independently of -active.
	// =========================
	var wordlist []string
	if opts.Wordlist != "" {
		wl, err := utils.ReadInputFromFile(opts.Wordlist)
		if err != nil {
			logify.Errorf("Error reading wordlist %s: %v", opts.Wordlist, err)
		} else {
			wordlist = wl
			logify.Infof("Loaded %d wordlist entries for fuzzing from %s", len(wordlist), opts.Wordlist)
		}
	}

	if opts.ActiveEnabled || len(wordlist) > 0 {
		activeSeeds := buildActiveSeedsFromQueries(opts.queries)
		logify.Infof("Started active-seed enumeration for %d seed target(s) (active=%v, fuzz=%v)", len(activeSeeds), opts.ActiveEnabled, len(wordlist) > 0)

		perTargetTimeout := time.Duration(opts.Timeout) * time.Second
		if perTargetTimeout <= 0 {
			perTargetTimeout = 30 * time.Second
		}

		if opts.ActiveEnabled {

			// 1) Crawl tool (Colly)
			crawlOpts := &crawl.Options{
				MaxDepth:    2,
				Parallelism: opts.ActiveConcurrency, // CHANGED
				Timeout:     perTargetTimeout,
				AllowQuery:  true,
			}

			// Run crawl concurrently over seeds (bounded)
			{
				seeds := append([]string(nil), activeSeeds...)
				seedJobs := make(chan string, len(seeds))
				var seedWG sync.WaitGroup

				for i := 0; i < crawlWorkers; i++ { // CHANGED
					seedWG.Add(1)
					go func() {
						defer seedWG.Done()
						for seed := range seedJobs {
							seedCtx, cancel := context.WithTimeout(context.Background(), perTargetTimeout)
							found, err := crawl.Enumerate(seedCtx, seed, opts.IncludeSubdomains, crawlOpts)
							cancel()

							if err != nil {
								logify.Errorf("crawl failed for %s: %v", seed, err)
								continue
							}
							for _, u := range found {
								addResult(u)
							}
						}

					}()
				}

				for _, s := range seeds {
					seedJobs <- s
				}
				close(seedJobs)
				seedWG.Wait()
			}

			// Refresh seeds after crawl added more
			resultsMu.Lock()
			uniqueURLs = uniqueURLs[:0]
			for _, u := range allResults {
				uniqueURLs = append(uniqueURLs, u)
			}

			resultsMu.Unlock()

			// 2) Headless tool (chromedp)
			headlessOpts := headless.Options{
				Concurrency: opts.ActiveConcurrency, // CHANGED
				Timeout:     perTargetTimeout,
				Wait:        8 * time.Second,
				//ChromePath:    "/usr/bin/google-chrome",
				Headless:      true,
				NoSandbox:     true,
				DisableGPU:    true,
				DisableDevShm: true,
			}

			// Run headless concurrently over seeds (bounded)
			{
				seeds := append([]string(nil), activeSeeds...)
				seedJobs := make(chan string, len(seeds))
				var seedWG sync.WaitGroup

				for i := 0; i < headlessWorkers; i++ { // CHANGED
					seedWG.Add(1)
					go func() {
						defer seedWG.Done()
						for seed := range seedJobs {
							seedCtx, cancel := context.WithTimeout(context.Background(), perTargetTimeout)
							found, err := headless.Enumerate(seedCtx, seed, opts.IncludeSubdomains, headlessOpts)
							cancel()

							if err != nil {
								logify.Errorf("headless failed for %s: %v", seed, err)
								continue
							}

							for _, u := range found {
								addResult(u)
							}
						}

					}()
				}

				for _, s := range seeds {
					seedJobs <- s
				}
				close(seedJobs)
				seedWG.Wait()
			}

		} // opts.ActiveEnabled (crawl + headless)

		// 3) Wordlist fuzzing (path/content discovery), independent of -active
		if len(wordlist) > 0 {
			fuzzOpts := fuzz.Options{
				Concurrency: opts.ActiveConcurrency,
				Timeout:     15 * time.Second,
			}
			fuzzWorkers := max(1, opts.ActiveConcurrency/2)

			seeds := append([]string(nil), activeSeeds...)
			seedJobs := make(chan string, len(seeds))
			var seedWG sync.WaitGroup

			for i := 0; i < fuzzWorkers; i++ {
				seedWG.Add(1)
				go func() {
					defer seedWG.Done()
					for seed := range seedJobs {
						seedCtx, cancel := context.WithTimeout(context.Background(), perTargetTimeout)
						found, err := fuzz.Enumerate(seedCtx, seed, wordlist, fuzzOpts)
						cancel()

						if err != nil {
							logify.Errorf("fuzz failed for %s: %v", seed, err)
							continue
						}
						for _, u := range found {
							addResult(u)
						}
					}
				}()
			}

			for _, s := range seeds {
				seedJobs <- s
			}
			close(seedJobs)
			seedWG.Wait()
		}

		resultsMu.Lock()
		total := len(allResults)
		resultsMu.Unlock()

		logify.Infof("Active-seed enumeration finished. Total unique URLs: %d", total)

		// Final unique list from map
		uniqueURLs = make([]string, 0, len(allResults))
		for _, u := range allResults {
			uniqueURLs = append(uniqueURLs, u)
		}
	}

	// Output
	if opts.Output != "" {
		if err := utils.WriteOutputToFile(opts.Output, uniqueURLs); err != nil {
			logify.Fatalf("Error writing output to file %s: %v", opts.Output, err)
		}
	}

	return nil
}

// dedupKey: generic dedupe key that ignores ALL query params and fragments.
// This ensures URLs that only differ by parameters are treated as duplicates.
func dedupKey(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil {
		// fallback if parsing fails
		return raw
	}

	u.Fragment = ""
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)

	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}

	// KEY POINT: ignore query entirely
	// If you want http/https to be treated the same, remove u.Scheme from the key.
	return u.Scheme + "://" + u.Host + p
}

// canonicalURL: returns the URL without query and fragment (safe for crawling/headless).
func canonicalURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}

	u.Fragment = ""
	u.RawQuery = "" // drop all params
	u.Host = strings.ToLower(u.Host)
	u.Scheme = strings.ToLower(u.Scheme)

	p := u.EscapedPath()
	if p == "" {
		p = "/"
	}
	p = path.Clean(p)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	u.Path = p

	return u.String()
}

func buildActiveSeedsFromQueries(queries []string) []string {
	out := make([]string, 0, len(queries))
	seen := make(map[string]struct{})

	for _, q := range queries {
		q = strings.TrimSpace(q)
		if q == "" || strings.HasPrefix(q, "#") {
			continue
		}

		// If user provided a full URL, parse it; otherwise treat as host.
		if !strings.Contains(q, "://") {
			q = "https://" + q
		}

		u, err := url.Parse(q)
		if err != nil {
			continue
		}

		host := strings.ToLower(strings.TrimSpace(u.Host))
		if host == "" {
			// sometimes the input might be like "example.com/path" without scheme,
			// after adding scheme it should parse, but just in case:
			host = strings.ToLower(strings.TrimSpace(u.Path))
		}
		if host == "" {
			continue
		}

		seed := "https://" + host + "/"
		if _, ok := seen[seed]; ok {
			continue
		}
		seen[seed] = struct{}{}
		out = append(out, seed)
	}
	return out
}
