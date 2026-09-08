package main

import (
	//"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	//"sync"

	//"github.com/corpix/uarand"
	//"github.com/chromedp/cdproto/input"
	"github.com/cyinnove/logify"
	"github.com/noureldinSAF/AutoHunting/jsAnalyzer/runner"
	"strings"
)

func main() {

	concurrency := flag.Int("c", 3, "Number of concurrent workers")
	inputFile := flag.String("i", "", "Input file with list of URLs (one per line)")
	output := flag.String("o", "output.txt", "Output file for results")
	subdomainsFlag := flag.Bool("subdomains", true, "Enumerate subdomains/domains")
	cloudFlag := flag.Bool("cloud", true, "Enumerate cloud buckets (S3/GCS/Azure)")
	endpointsFlag := flag.Bool("endpoints", true, "Enumerate endpoints/URLs")
	paramsFlag := flag.Bool("params", true, "Enumerate parameters")
	npmFlag := flag.Bool("npm", true, "Enumerate npm/node_modules packages")
	secretsFlag := flag.Bool("secrets", true, "Find secrets (keys/tokens/etc)")
	timeout := flag.Int("timeout", 60, "Timeout in seconds for each URL scan")

	onlyFlag := flag.String("only", "", "Comma-separated: subdomains,cloud,endpoints,params,npm,secrets (disables others)")

	flag.Parse()

	opts := runner.AnalyzeOptions{
		Subdomains: *subdomainsFlag,
		Cloud:      *cloudFlag,
		Endpoints:  *endpointsFlag,
		Params:     *paramsFlag,
		Npm:        *npmFlag,
		Secrets:    *secretsFlag,
		Timeout:    time.Duration(*timeout) * time.Second,
	}
	logify.Infof("HTTP timeout: %s", opts.Timeout)

	if strings.TrimSpace(*onlyFlag) != "" {
		o := runner.Only(*onlyFlag)
		o.Timeout = opts.Timeout // preserve timeout!
		opts = o
	}

	if *inputFile == "" {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "[options] <url1> <url2> ...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	urls, err := runner.ReadInputFromFile(*inputFile)
	if err != nil {
		logify.Errorf("Error reading input file %s: %v", *inputFile, err)
		os.Exit(1)
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "Usage:", os.Args[0], "[options] <url1> <url2> ...")
		flag.PrintDefaults()
		os.Exit(1)
	}

	logify.Infof("Scanning %d URLs with %d concurrent workers", len(urls), *concurrency)

	logify.Infof("Enabled: subdomains=%v cloud=%v endpoints=%v params=%v npm=%v secrets=%v",
		opts.Subdomains, opts.Cloud, opts.Endpoints, opts.Params, opts.Npm, opts.Secrets)

	results, err := runner.ScanJSURLs(urls, *concurrency, opts)
	if err != nil {
		logify.Errorf("Error scanning URLs: %v", err)
	}

	// When secrets is the only thing being scanned for, the per-URL result
	// shape isn't useful: most URLs have no secret at all, and the same
	// leaked value often shows up verbatim across many bundled/minified
	// files. Group by secret instead, dropping URLs with no match and
	// collapsing duplicate secrets into one entry with all their URLs.
	secretsOnly := opts.Secrets && !opts.Subdomains && !opts.Cloud && !opts.Endpoints && !opts.Params && !opts.Npm

	var data []byte
	if secretsOnly {
		groups := runner.GroupSecretsByValue(results)
		data, err = runner.EncodeSecretGroups(groups)
		logify.Infof("Found %d distinct secret(s) across %d scanned URL(s)", len(groups), len(results))
	} else {
		data, err = runner.EncodeResults(results)
	}
	if err != nil {
		logify.Errorf("Error encoding results: %v", err)
		os.Exit(1)
	}

	if *output == "" {
		if _, err := os.Stdout.Write(data); err != nil {
			logify.Errorf("Error writing to stdout: %v", err)
			os.Exit(1)
		}
	} else {
		if err := os.WriteFile(*output, data, 0644); err != nil {
			logify.Errorf("Error writing to file %s: %v", *output, err)
			os.Exit(1)
		}
		logify.Infof("Results written to %s", *output)
	}

}
