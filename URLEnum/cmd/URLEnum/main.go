package main

import (
	"flag"
	"os"
	"time"

	"github.com/cyinnove/logify"
	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/runner"
)

func main() {
	startTime := time.Now()

	options := &runner.Options{}
	flag.StringVar(&options.Domain, "d", "", "Domain to enumerate URLs for")
	flag.StringVar(&options.Input, "i", "", "Input file with list of URLs")
	flag.StringVar(&options.Output, "o", "results.txt", "Output file for results")

	flag.IntVar(&options.Timeout, "timeout", 30, "Timeout for each request in seconds")
	flag.IntVar(&options.Concurrency, "c", 8, "Number of concurrent passive/active workers")

	flag.BoolVar(&options.ActiveEnabled, "active", false, "Enable active scanning mode (crawl + headless)")
	flag.BoolVar(&options.IncludeSubdomains, "subs", false, "Include subdomains in active scanning")
	flag.IntVar(&options.Depth, "depth", 3, "Maximum active crawl depth")
	flag.IntVar(&options.MaxActiveSeeds, "max-seeds", 300, "Maximum active crawl/headless seeds")
	flag.BoolVar(&options.HeadlessEnabled, "headless", true, "Enable headless stage when active scanning is enabled")

	flag.StringVar(&options.DedupeMode, "dedupe", "param", "Dedupe mode: exact, param, or path")

	flag.BoolVar(&options.Workflow, "workflow", false, "Generate workflow output files")
	flag.StringVar(&options.WorkflowOut, "workflow-out", "urlenum-workflow", "Workflow output directory")
	flag.IntVar(&options.WorkflowScore, "workflow-score", 60, "Minimum interesting score for workflow output")

	flag.BoolVar(&options.FuzzPlan, "fuzz-plan", false, "Generate ffuf review plan files")
	flag.StringVar(&options.FuzzOutDir, "fuzz-out", "", "Fuzz plan output directory")
	flag.StringVar(&options.FuzzMarker, "fuzz-marker", "FUZZ", "Fuzz marker used in generated URLs")
	flag.StringVar(&options.FuzzWordlist, "fuzz-wordlist", "payloads.txt", "Wordlist path used in generated ffuf commands")
	flag.IntVar(&options.FuzzRate, "fuzz-rate", 20, "Rate limit used in generated ffuf commands")
	flag.IntVar(&options.FuzzMinScore, "fuzz-min-score", 3, "Minimum fuzz target score")

	flag.BoolVar(&options.NucleiPlan, "nuclei-plan", false, "Generate nuclei review plan files")
	flag.StringVar(&options.NucleiOutDir, "nuclei-out", "", "Nuclei plan output directory")
	flag.IntVar(&options.NucleiRate, "nuclei-rate", 20, "Rate limit used in generated nuclei commands")
	flag.StringVar(&options.NucleiTags, "nuclei-tags", "", "Comma-separated extra nuclei tags")

	flag.BoolVar(&options.JSSecrets, "js-secrets", false, "Extract discovered JS URLs and scan them with jsAnalyzer for secrets")
	flag.StringVar(&options.JSOutDir, "js-out", "", "JS secret scan output directory")
	flag.IntVar(&options.JSConcurrency, "js-c", 3, "jsAnalyzer worker concurrency")
	flag.IntVar(&options.JSTimeout, "js-timeout", 30, "jsAnalyzer fetch timeout per JS URL in seconds")
	flag.IntVar(&options.JSRetries, "js-retries", 3, "jsAnalyzer retries per JS URL")
	flag.Int64Var(&options.JSMaxSize, "js-max-size", 5*1024*1024, "Maximum JS response size in bytes")
	flag.BoolVar(&options.JSStrict, "js-strict", false, "Require JavaScript content type while fetching JS URLs")
	flag.BoolVar(&options.JSRawSecrets, "js-raw-secrets", false, "Write raw secret values in JS secret outputs")

	flag.Parse()

	if err := runner.Run(options); err != nil {
		logify.Errorf("Error running URL enumeration: %v", err)
		os.Exit(1)
	}

	elapsed := time.Since(startTime)
	logify.Infof("URL enumeration completed in %s", elapsed)
}
