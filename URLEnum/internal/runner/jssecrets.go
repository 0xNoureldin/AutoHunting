package runner

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cyinnove/logify"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/utils"
	jsrunner "github.com/noureldinSAF/AutoHunting/jsAnalyzer/runner"
)

const (
	jsURLsFile    = "js-urls.txt"
	jsResultsFile = "js-results.json"
	jsSecretsFile = "secrets.jsonl"
	jsSummaryFile = "summary.md"
)

func runJSSecretStage(urls []string, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}

	jsURLs := extractJSURLs(urls)
	if err := os.MkdirAll(opts.JSOutDir, 0755); err != nil {
		return err
	}

	if err := utils.WriteOutputToFile(filepath.Join(opts.JSOutDir, jsURLsFile), jsURLs); err != nil {
		return err
	}

	logify.Infof("js secrets stage: %d JS URLs selected from %d URLs", len(jsURLs), len(urls))

	var (
		results = []jsrunner.ScanResult{}
		scanErr error
	)
	if len(jsURLs) > 0 {
		if opts.JSRawSecrets {
			logify.Infof("js secrets stage: raw secret output is enabled")
		}
		results, scanErr = jsrunner.ScanJSURLs(jsURLs, opts.JSConcurrency, jsAnalyzeOptions(opts))
		if scanErr != nil {
			logify.Errorf("js secrets stage completed with per-URL errors: %v", scanErr)
		}
	}

	data, err := jsrunner.EncodeResults(results)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(opts.JSOutDir, jsResultsFile), data, 0644); err != nil {
		return err
	}
	if err := jsrunner.WriteSecretsJSONL(filepath.Join(opts.JSOutDir, jsSecretsFile), results, opts.JSRawSecrets); err != nil {
		return err
	}
	if err := writeJSSecretSummary(filepath.Join(opts.JSOutDir, jsSummaryFile), jsURLs, results, scanErr, opts); err != nil {
		return err
	}

	logify.Infof("js secrets stage complete: %d findings written to %s", countJSSecrets(results), opts.JSOutDir)
	return nil
}

func jsAnalyzeOptions(opts *Options) jsrunner.AnalyzeOptions {
	return jsrunner.AnalyzeOptions{
		Secrets:     true,
		Timeout:     time.Duration(opts.JSTimeout) * time.Second,
		Retries:     opts.JSRetries,
		MaxSize:     opts.JSMaxSize,
		StrictJS:    opts.JSStrict,
		RawSecrets:  opts.JSRawSecrets,
		Deobfuscate: true,
		MaxFindings: 5000,
	}
}

func extractJSURLs(urls []string) []string {
	seen := make(map[string]struct{}, len(urls))
	out := make([]string, 0, len(urls))
	for _, raw := range urls {
		canonical := canonicalJSURL(raw)
		if canonical == "" {
			continue
		}
		if _, ok := seen[canonical]; ok {
			continue
		}
		seen[canonical] = struct{}{}
		out = append(out, canonical)
	}
	sort.Strings(out)
	return out
}

func canonicalJSURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}

	pathLower := strings.ToLower(u.Path)
	if pathLower == "" {
		return ""
	}
	if strings.HasSuffix(pathLower, ".js.map") ||
		strings.HasSuffix(pathLower, ".map") ||
		strings.HasSuffix(pathLower, ".js.json") ||
		strings.HasSuffix(pathLower, ".json") {
		return ""
	}
	if !strings.HasSuffix(pathLower, ".js") &&
		!strings.HasSuffix(pathLower, ".mjs") &&
		!strings.HasSuffix(pathLower, ".cjs") {
		return ""
	}

	u.Scheme = scheme
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	return u.String()
}

func writeJSSecretSummary(path string, jsURLs []string, results []jsrunner.ScanResult, scanErr error, opts *Options) error {
	lines := []string{
		"# JS Secret Scan Summary",
		"",
		fmt.Sprintf("- JS URLs selected: %d", len(jsURLs)),
		fmt.Sprintf("- JS URLs scanned successfully: %d", len(results)),
		fmt.Sprintf("- Secret findings: %d", countJSSecrets(results)),
		fmt.Sprintf("- Raw secrets written: %v", opts.JSRawSecrets),
		fmt.Sprintf("- Strict JavaScript content type: %v", opts.JSStrict),
		fmt.Sprintf("- Fetch retries: %d", opts.JSRetries),
		"",
		"Generated files:",
		"- " + jsURLsFile,
		"- " + jsResultsFile,
		"- " + jsSecretsFile,
	}
	if scanErr != nil {
		lines = append(lines, "", "Scan completed with per-URL errors:", "- "+scanErr.Error())
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0644)
}

func countJSSecrets(results []jsrunner.ScanResult) int {
	total := 0
	for _, result := range results {
		total += len(result.SecretFindings)
	}
	return total
}
