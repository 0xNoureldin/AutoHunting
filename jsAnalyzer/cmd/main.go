package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/cyinnove/logify"
	"github.com/noureldinSAF/AutoHunting/jsAnalyzer/runner"
)

func main() {
	concurrency := flag.Int("c", 3, "Number of concurrent workers")
	inputFile := flag.String("i", "", "Input file with list of JS URLs")
	singleURL := flag.String("u", "", "Single JS URL to analyze")
	output := flag.String("o", "output.json", "Output JSON file, or empty for stdout")
	jsonOutput := flag.Bool("json", true, "Write JSON results to -o/stdout")
	endpointsOut := flag.String("endpoints-out", "", "Optional plaintext endpoints output file")
	secretsOut := flag.String("secrets-out", "", "Optional JSONL secrets output file")

	subdomainsFlag := flag.Bool("subdomains", true, "Enumerate subdomains/domains")
	cloudFlag := flag.Bool("cloud", true, "Enumerate cloud buckets (S3/GCS/Azure)")
	endpointsFlag := flag.Bool("endpoints", true, "Enumerate endpoints/URLs")
	paramsFlag := flag.Bool("params", true, "Enumerate parameters")
	npmFlag := flag.Bool("npm", true, "Enumerate npm/node_modules packages")
	secretsFlag := flag.Bool("secrets", true, "Find secrets (keys/tokens/etc)")
	onlyFlag := flag.String("only", "", "Comma-separated: subdomains,cloud,endpoints,params,npm,secrets (disables others)")

	timeout := flag.Int("timeout", 30, "Timeout in seconds for each JS URL fetch")
	retries := flag.Int("retries", 3, "Number of retries for transient fetch failures")
	maxSize := flag.Int64("max-size", 5*1024*1024, "Maximum JS response size in bytes")
	strictJS := flag.Bool("strict-js", false, "Reject responses without a JavaScript content type")
	rawSecrets := flag.Bool("raw-secrets", true, "Include complete raw secret values in JSON outputs; set false to mask")
	deobfuscate := flag.Bool("deobfuscate", true, "Enable safe static deobfuscation/unpacking")
	maxFindings := flag.Int("max-findings", 5000, "Maximum endpoints and secrets retained per JS file")

	flag.Parse()

	opts := runner.AnalyzeOptions{
		Subdomains:  *subdomainsFlag,
		Cloud:       *cloudFlag,
		Endpoints:   *endpointsFlag,
		Params:      *paramsFlag,
		Npm:         *npmFlag,
		Secrets:     *secretsFlag,
		Timeout:     time.Duration(*timeout) * time.Second,
		Retries:     *retries,
		MaxSize:     *maxSize,
		StrictJS:    *strictJS,
		RawSecrets:  *rawSecrets,
		Deobfuscate: *deobfuscate,
		MaxFindings: *maxFindings,
	}

	if strings.TrimSpace(*onlyFlag) != "" {
		only := runner.Only(*onlyFlag)
		only.Timeout = opts.Timeout
		only.Retries = opts.Retries
		only.MaxSize = opts.MaxSize
		only.StrictJS = opts.StrictJS
		only.RawSecrets = opts.RawSecrets
		only.Deobfuscate = opts.Deobfuscate
		only.MaxFindings = opts.MaxFindings
		opts = only
	}

	urls, err := collectInputURLs(*singleURL, *inputFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		flag.PrintDefaults()
		os.Exit(1)
	}

	logify.Infof("Scanning %d JS URLs with %d concurrent workers", len(urls), *concurrency)
	logify.Infof("Enabled: subdomains=%v cloud=%v endpoints=%v params=%v npm=%v secrets=%v deobfuscate=%v",
		opts.Subdomains, opts.Cloud, opts.Endpoints, opts.Params, opts.Npm, opts.Secrets, opts.Deobfuscate)

	results, scanErr := runner.ScanJSURLs(urls, *concurrency, opts)
	if scanErr != nil {
		logify.Errorf("Completed with per-URL errors: %v", scanErr)
	}

	if *jsonOutput {
		data, err := runner.EncodeResults(results)
		if err != nil {
			logify.Errorf("Error encoding results: %v", err)
			os.Exit(1)
		}
		if strings.TrimSpace(*output) == "" {
			if _, err := os.Stdout.Write(data); err != nil {
				logify.Errorf("Error writing JSON to stdout: %v", err)
				os.Exit(1)
			}
		} else {
			if err := os.WriteFile(*output, data, 0644); err != nil {
				logify.Errorf("Error writing JSON to %s: %v", *output, err)
				os.Exit(1)
			}
			logify.Infof("JSON results written to %s", *output)
		}
	}

	if strings.TrimSpace(*endpointsOut) != "" {
		if err := runner.WriteEndpoints(*endpointsOut, results); err != nil {
			logify.Errorf("Error writing endpoints to %s: %v", *endpointsOut, err)
			os.Exit(1)
		}
		logify.Infof("Endpoints written to %s", *endpointsOut)
	}

	if strings.TrimSpace(*secretsOut) != "" {
		if err := runner.WriteSecretsJSONL(*secretsOut, results, opts.RawSecrets); err != nil {
			logify.Errorf("Error writing secrets to %s: %v", *secretsOut, err)
			os.Exit(1)
		}
		logify.Infof("Secrets written to %s", *secretsOut)
	}
}

func collectInputURLs(singleURL, inputFile string) ([]string, error) {
	urls := []string{}
	if strings.TrimSpace(singleURL) != "" {
		urls = append(urls, singleURL)
	}
	if strings.TrimSpace(inputFile) != "" {
		fileURLs, err := runner.ReadInputFromFile(inputFile)
		if err != nil {
			return nil, fmt.Errorf("error reading input file %s: %w", inputFile, err)
		}
		urls = append(urls, fileURLs...)
	}
	if len(runnerOnlySanitize(urls)) == 0 {
		return nil, fmt.Errorf("Usage: provide -u or -i with at least one http(s) JS URL")
	}
	return urls, nil
}

func runnerOnlySanitize(urls []string) []string {
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		u = strings.TrimSpace(u)
		if strings.HasPrefix(strings.ToLower(u), "http://") || strings.HasPrefix(strings.ToLower(u), "https://") {
			out = append(out, u)
		}
	}
	return out
}
