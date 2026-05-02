package runner

import (
	"context"
	"errors"
	"math/rand"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/cyinnove/logify"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/fuzz"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/nuclei"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/priority"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/workflow"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/active/crawl"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/active/headless"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper/sources"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/utils"
)

func RunPipeline(opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}

	queries, err := loadQueries(opts)
	if err != nil {
		return err
	}
	opts.queries = queries
	setDefaults(opts)

	apiKeys, err := scraper.ExtractALLAPIKeys()
	if err != nil {
		return err
	}

	store := newResultStore(parseDedupeMode(opts.DedupeMode))
	ctx := context.Background()
	srcs := sources.GetAllSources(apiKeys)
	limiters := map[string]*limiter{}
	for _, src := range srcs {
		limiters[src.Name()] = limiterForSource(src.Name())
	}

	logify.Infof("passive stage: %d queries, %d sources, concurrency=%d", len(queries), len(srcs), opts.Concurrency)
	runPassiveStage(ctx, opts, queries, srcs, limiters, store)
	logify.Infof("passive stage complete: %d unique URLs", store.Len())

	if opts.ActiveEnabled {
		if err := runActiveStage(ctx, opts, queries, store); err != nil {
			logify.Errorf("active stage completed with errors: %v", err)
		}
	}

	urls := priority.Sort(store.List())
	if opts.Output != "" {
		if err := utils.WriteOutputToFile(opts.Output, urls); err != nil {
			return err
		}
	}

	if opts.Workflow {
		if err := workflow.Run(urls, workflowOptions(opts)); err != nil {
			return err
		}
	}

	if opts.JSSecrets {
		if err := runJSSecretStage(urls, opts); err != nil {
			return err
		}
	}

	return nil
}

func setDefaults(opts *Options) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 30
	}
	if opts.Depth <= 0 {
		opts.Depth = 3
	}
	if opts.MaxActiveSeeds <= 0 {
		opts.MaxActiveSeeds = 300
	}
	if strings.TrimSpace(opts.DedupeMode) == "" {
		opts.DedupeMode = "param"
	}
	if strings.TrimSpace(opts.WorkflowOut) == "" {
		opts.WorkflowOut = "urlenum-workflow"
	}
	if opts.WorkflowScore <= 0 {
		opts.WorkflowScore = 60
	}
	if strings.TrimSpace(opts.FuzzMarker) == "" {
		opts.FuzzMarker = "FUZZ"
	}
	if strings.TrimSpace(opts.FuzzWordlist) == "" {
		opts.FuzzWordlist = "payloads.txt"
	}
	if opts.FuzzRate <= 0 {
		opts.FuzzRate = 20
	}
	if opts.FuzzMinScore <= 0 {
		opts.FuzzMinScore = 3
	}
	if opts.NucleiRate <= 0 {
		opts.NucleiRate = 20
	}
	if opts.JSConcurrency <= 0 {
		opts.JSConcurrency = 3
	}
	if opts.JSTimeout <= 0 {
		opts.JSTimeout = 30
	}
	if opts.JSRetries < 0 {
		opts.JSRetries = 0
	}
	if opts.JSMaxSize <= 0 {
		opts.JSMaxSize = 5 * 1024 * 1024
	}
	if strings.TrimSpace(opts.JSOutDir) == "" {
		if opts.Workflow {
			opts.JSOutDir = filepath.Join(opts.WorkflowOut, "js-secrets")
		} else {
			opts.JSOutDir = "urlenum-js-secrets"
		}
	}
}

func runPassiveStage(
	ctx context.Context,
	opts *Options,
	queries []string,
	srcs []scraper.Source,
	limiters map[string]*limiter,
	store *resultStore,
) {
	passiveJobs := make(chan passiveJob)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range passiveJobs {
				urls, err := runPassiveSourceWithRetry(ctx, opts, job, limiters[job.source.Name()])
				if err != nil {
					logify.Errorf("source %s failed for %s after retries: %v", job.source.Name(), job.query, err)
					continue
				}
				for _, u := range urls {
					store.Add(u, job.source.Name())
				}
			}
		}()
	}

	for _, q := range queries {
		for _, src := range srcs {
			passiveJobs <- passiveJob{query: q, source: src}
		}
	}
	close(passiveJobs)
	wg.Wait()
}

type passiveJob struct {
	query  string
	source scraper.Source
}

func runPassiveSourceWithRetry(ctx context.Context, opts *Options, job passiveJob, lim *limiter) ([]string, error) {
	attempts := passiveRetryAttempts(job.source.Name())
	var lastErr error

	for attempt := 1; attempt <= attempts; attempt++ {
		if err := lim.Wait(ctx); err != nil {
			return nil, err
		}

		requestTimeout := passiveRequestTimeout(opts, job.source.Name())
		attemptBudget := passiveAttemptBudget(opts, job.source.Name(), requestTimeout)
		attemptCtx, cancel := context.WithTimeout(ctx, attemptBudget)
		client := scraper.NewSession(secondsCeil(requestTimeout))

		urls, err := job.source.Search(attemptCtx, job.query, client)
		cancel()
		if err == nil {
			if attempt > 1 {
				logify.Infof("source %s recovered for %s on attempt %d/%d with %d urls", job.source.Name(), job.query, attempt, attempts, len(urls))
			}
			return urls, nil
		}

		lastErr = err
		if !isRetryablePassiveErr(err) || attempt == attempts {
			break
		}

		logify.Infof("source %s failed for %s: %v; retrying attempt %d/%d", job.source.Name(), job.query, err, attempt+1, attempts)
		if err := sleepPassiveRetry(ctx, attempt); err != nil {
			return nil, err
		}
	}

	return nil, lastErr
}

func passiveRetryAttempts(sourceName string) int {
	switch strings.ToLower(strings.TrimSpace(sourceName)) {
	case "webarchive":
		return 2
	default:
		return 2
	}
}

func passiveRequestTimeout(opts *Options, sourceName string) time.Duration {
	configured := time.Duration(opts.Timeout) * time.Second
	if configured <= 0 {
		configured = 30 * time.Second
	}

	var capTimeout time.Duration
	switch strings.ToLower(strings.TrimSpace(sourceName)) {
	case "webarchive":
		capTimeout = 5 * time.Second
	case "commoncrawl":
		capTimeout = 10 * time.Second
	default:
		capTimeout = 10 * time.Second
	}
	if configured < capTimeout {
		return configured
	}
	return capTimeout
}

func passiveAttemptBudget(opts *Options, sourceName string, requestTimeout time.Duration) time.Duration {
	switch strings.ToLower(strings.TrimSpace(sourceName)) {
	case "webarchive":
		return requestTimeout + 3*time.Second
	case "commoncrawl":
		return requestTimeout * 2
	default:
		return requestTimeout + 2*time.Second
	}
}

func isRetryablePassiveErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	msg := strings.ToLower(err.Error())
	for _, token := range []string{
		"retryable",
		"timeout",
		"temporary",
		"connection refused",
		"connection reset",
		"tls handshake timeout",
		"i/o timeout",
		"dial tcp",
		"no such host",
		"eof",
		"status 429",
		"status 500",
		"status 502",
		"status 503",
		"status 504",
		"too many requests",
	} {
		if strings.Contains(msg, token) {
			return true
		}
	}
	return false
}

func sleepPassiveRetry(ctx context.Context, attempt int) error {
	base := 250 * time.Millisecond
	maxDelay := 2 * time.Second
	delay := base * time.Duration(1<<(attempt-1))
	if delay > maxDelay {
		delay = maxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(delay / 2)))
	t := time.NewTimer(delay + jitter)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func secondsCeil(d time.Duration) int {
	if d <= 0 {
		return 1
	}
	return int((d + time.Second - 1) / time.Second)
}

func runActiveStage(ctx context.Context, opts *Options, queries []string, store *resultStore) error {
	seeds := activeSeeds(queries, store.List(), opts.MaxActiveSeeds)
	if len(seeds) == 0 {
		return nil
	}

	logify.Infof("active stage: %d seeds, depth=%d, concurrency=%d", len(seeds), opts.Depth, opts.Concurrency)
	perTargetTimeout := time.Duration(opts.Timeout) * time.Second
	jobs := make(chan string)
	var wg sync.WaitGroup
	crawlOpts := &crawl.Options{MaxDepth: opts.Depth, Parallelism: opts.Concurrency, Timeout: perTargetTimeout, AllowQuery: true}
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seed := range jobs {
				stageCtx, cancel := context.WithTimeout(ctx, perTargetTimeout)
				found, err := crawl.Enumerate(stageCtx, seed, opts.IncludeSubdomains, crawlOpts)
				cancel()
				if err != nil {
					logify.Errorf("crawl failed for %s: %v", seed, err)
					continue
				}
				for _, u := range found {
					store.Add(u, "crawl")
				}
			}
		}()
	}
	for _, seed := range seeds {
		jobs <- seed
	}
	close(jobs)
	wg.Wait()
	logify.Infof("crawl stage complete: %d unique URLs", store.Len())

	if !opts.HeadlessEnabled {
		return nil
	}

	headlessSeeds := selectHeadlessSeeds(store.List(), max(1, opts.MaxActiveSeeds/2))
	if len(headlessSeeds) == 0 {
		return nil
	}

	headlessConcurrency := max(1, opts.Concurrency/2)
	logify.Infof("headless stage: %d seeds, concurrency=%d", len(headlessSeeds), headlessConcurrency)
	hJobs := make(chan string)
	var hWG sync.WaitGroup
	headlessOpts := headless.Options{Concurrency: headlessConcurrency, Timeout: perTargetTimeout, Wait: 5 * time.Second, Headless: true, NoSandbox: true, DisableGPU: true, DisableDevShm: true}
	for i := 0; i < headlessConcurrency; i++ {
		hWG.Add(1)
		go func() {
			defer hWG.Done()
			for seed := range hJobs {
				stageCtx, cancel := context.WithTimeout(ctx, perTargetTimeout)
				found, err := headless.Enumerate(stageCtx, seed, opts.IncludeSubdomains, headlessOpts)
				cancel()
				if err != nil {
					logify.Errorf("headless failed for %s: %v", seed, err)
					continue
				}
				for _, u := range found {
					store.Add(u, "headless")
				}
			}
		}()
	}
	for _, seed := range headlessSeeds {
		hJobs <- seed
	}
	close(hJobs)
	hWG.Wait()
	logify.Infof("headless stage complete: %d unique URLs", store.Len())
	return nil
}

func loadQueries(opts *Options) ([]string, error) {
	if opts == nil || (strings.TrimSpace(opts.Domain) == "" && strings.TrimSpace(opts.Input) == "") {
		return nil, ErrNoInput
	}

	seen := map[string]struct{}{}
	queries := make([]string, 0)
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return
		}
		if _, ok := seen[raw]; ok {
			return
		}
		seen[raw] = struct{}{}
		queries = append(queries, raw)
	}

	for _, q := range utils.ExtractDomainsFromString(opts.Domain) {
		add(q)
	}
	if strings.TrimSpace(opts.Input) != "" {
		lines, err := utils.ReadInputFromFile(opts.Input)
		if err != nil {
			return nil, err
		}
		for _, q := range lines {
			add(q)
		}
	}
	if len(queries) == 0 {
		return nil, ErrNoInput
	}
	return queries, nil
}

func workflowOptions(opts *Options) workflow.Options {
	return workflow.Options{
		Enabled:          opts.Workflow,
		OutDir:           opts.WorkflowOut,
		InterestingScore: opts.WorkflowScore,
		FuzzEnabled:      opts.FuzzPlan,
		NucleiEnabled:    opts.NucleiPlan,
		Fuzz: fuzz.PlanOptions{
			Enabled:  opts.FuzzPlan,
			OutDir:   opts.FuzzOutDir,
			Marker:   opts.FuzzMarker,
			Wordlist: opts.FuzzWordlist,
			Rate:     opts.FuzzRate,
			MinScore: opts.FuzzMinScore,
		},
		Nuclei: nuclei.PlanOptions{
			Enabled: opts.NucleiPlan,
			OutDir:  opts.NucleiOutDir,
			Rate:    opts.NucleiRate,
			Tags:    splitCSV(opts.NucleiTags),
		},
	}
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
