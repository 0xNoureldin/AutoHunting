package runner

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/cyinnove/logify"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/active/crawl"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/active/headless"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/scraper/sources"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/utils"
)

func RunPipeline(opts *Options) error {
	queries, err := loadQueries(opts)
	if err != nil {
		return err
	}
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

	apiKeys, err := scraper.ExtractALLAPIKeys()
	if err != nil {
		return err
	}

	store := newResultStore(parseDedupeMode(opts.DedupeMode))
	ctx := context.Background()
	client := scraper.NewSession(opts.Timeout)
	srcs := sources.GetAllSources(apiKeys)
	limiters := map[string]*limiter{}
	for _, src := range srcs {
		limiters[src.Name()] = limiterForSource(src.Name())
	}

	logify.Infof("passive stage: %d queries, %d sources, concurrency=%d", len(queries), len(srcs), opts.Concurrency)
	passiveJobs := make(chan passiveJob)
	var wg sync.WaitGroup
	for i := 0; i < opts.Concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range passiveJobs {
				stageCtx, cancel := context.WithTimeout(ctx, time.Duration(opts.Timeout)*time.Second)
				lim := limiters[job.source.Name()]
				if err := lim.Wait(stageCtx); err != nil {
					cancel()
					continue
				}
				urls, err := job.source.Search(stageCtx, job.query, client)
				cancel()
				if err != nil {
					if job.source.Name() != "commoncrawl" {
						logify.Errorf("source %s failed for %s: %v", job.source.Name(), job.query, err)
					}
					continue
				}
				for _, u := range urls {
					store.Add(u, job.source.Name())
				}
			}
		}()
	}
	for _, q := range queries {
		q = strings.TrimSpace(q)
		if q == "" || strings.HasPrefix(q, "#") {
			continue
		}
		for _, src := range srcs {
			passiveJobs <- passiveJob{query: q, source: src}
		}
	}
	close(passiveJobs)
	wg.Wait()
	logify.Infof("passive stage complete: %d unique URLs", store.Len())

	if opts.ActiveEnabled {
		if err := runActiveStage(ctx, opts, queries, store); err != nil {
			logify.Errorf("active stage completed with errors: %v", err)
		}
	}

	if opts.Output != "" {
		return utils.WriteOutputToFile(opts.Output, store.List())
	}
	return nil
}

type passiveJob struct {
	query  string
	source scraper.Source
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
	headlessSeeds := activeSeeds(nil, store.List(), opts.MaxActiveSeeds/2)
	hJobs := make(chan string)
	var hWG sync.WaitGroup
	headlessOpts := headless.Options{Concurrency: max(1, opts.Concurrency/2), Timeout: perTargetTimeout, Wait: 5 * time.Second, Headless: true, NoSandbox: true, DisableGPU: true, DisableDevShm: true}
	for i := 0; i < max(1, opts.Concurrency/2); i++ {
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
	if opts.Domain == "" && opts.Input == "" {
		return nil, ErrNoInput
	}
	queries := utils.ExtractDomainsFromString(opts.Domain)
	if opts.Input != "" {
		return utils.ReadInputFromFile(opts.Input)
	}
	return queries, nil
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
