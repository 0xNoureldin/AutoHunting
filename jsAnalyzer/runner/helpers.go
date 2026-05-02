package runner

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

type MultiError struct{ Errs []error }

func (m MultiError) Error() string {
	if len(m.Errs) == 0 {
		return ""
	}
	if len(m.Errs) == 1 {
		return m.Errs[0].Error()
	}
	return fmt.Sprintf("%s (and %d more errors)", m.Errs[0], len(m.Errs)-1)
}

func defaultOptions(opts AnalyzeOptions) AnalyzeOptions {
	if opts.Timeout <= 0 {
		opts.Timeout = 30 * time.Second
	}
	if opts.Retries <= 0 {
		opts.Retries = 3
	}
	if opts.MaxSize <= 0 {
		opts.MaxSize = 5 * 1024 * 1024
	}
	if opts.MaxFindings <= 0 {
		opts.MaxFindings = 5000
	}
	return opts
}

func ScanJSURLs(urls []string, concurrency int, opts AnalyzeOptions) ([]ScanResult, error) {
	opts = defaultOptions(opts)
	urls = sanitizeURLs(urls)
	if len(urls) == 0 {
		return []ScanResult{}, fmt.Errorf("no valid http(s) URLs provided")
	}
	if concurrency <= 0 {
		concurrency = 1
	}

	fetcher := NewFetcher(opts)
	results := make([]ScanResult, len(urls))
	ok := make([]bool, len(urls))
	errs := make(chan error, len(urls))
	jobs := make(chan int)

	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				u := urls[idx]
				res, err := ScanJSURLWithFetcher(u, opts, fetcher)
				if err != nil {
					errs <- fmt.Errorf("error scanning %s: %w", u, err)
					continue
				}
				results[idx] = res
				ok[idx] = true
			}
		}()
	}

	for i := range urls {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	close(errs)

	final := make([]ScanResult, 0, len(urls))
	for i := range results {
		if ok[i] {
			final = append(final, results[i])
		}
	}

	var allErrs []error
	for err := range errs {
		allErrs = append(allErrs, err)
	}
	if len(allErrs) > 0 {
		return final, MultiError{Errs: allErrs}
	}
	return final, nil
}

func ScanJSURL(rawURL string, opts AnalyzeOptions) (ScanResult, error) {
	return ScanJSURLWithFetcher(rawURL, opts, NewFetcher(defaultOptions(opts)))
}

func ScanJSURLWithFetcher(rawURL string, opts AnalyzeOptions, fetcher *Fetcher) (ScanResult, error) {
	opts = defaultOptions(opts)
	res, err := fetcher.Fetch(rawURL)
	if err != nil {
		return ScanResult{}, err
	}

	scan, err := AnalyzeJSContentForURL(res.URL, res.Body, opts)
	if err != nil {
		return ScanResult{}, err
	}
	scan.URL = res.URL
	return scan, nil
}

func GetContent(rawURL string, opts AnalyzeOptions) (string, error) {
	res, err := NewFetcher(defaultOptions(opts)).Fetch(rawURL)
	if err != nil {
		return "", err
	}
	return string(res.Body), nil
}

func EncodeResults(results []ScanResult) ([]byte, error) {
	return json.MarshalIndent(results, "", "  ")
}

func ReadInputFromFile(file string) ([]string, error) {
	fileData, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return strings.Split(string(fileData), "\n"), nil
}

func WriteOutputToFile(file string, data []string) error {
	f, err := os.Create(file)
	if err != nil {
		return err
	}
	defer f.Close()

	writer := bufio.NewWriter(f)
	for _, line := range data {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}

	return writer.Flush()
}

func ExtractDomainsFromString(input string) []string {
	return strings.Split(input, ",")
}

func sanitizeURLs(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, u := range in {
		u = strings.TrimSpace(u)
		if u == "" || strings.HasPrefix(u, "#") {
			continue
		}
		if !strings.HasPrefix(strings.ToLower(u), "http://") && !strings.HasPrefix(strings.ToLower(u), "https://") {
			continue
		}
		if _, ok := seen[u]; ok {
			continue
		}
		seen[u] = struct{}{}
		out = append(out, u)
	}
	return out
}

func Only(list string) AnalyzeOptions {
	var o AnalyzeOptions
	for _, item := range strings.Split(list, ",") {
		switch strings.ToLower(strings.TrimSpace(item)) {
		case "subdomains":
			o.Subdomains = true
		case "cloud":
			o.Cloud = true
		case "endpoints":
			o.Endpoints = true
		case "params":
			o.Params = true
		case "npm":
			o.Npm = true
		case "secrets":
			o.Secrets = true
		}
	}
	return o
}

func setToSlice(set map[string]struct{}) []string {
	slice := make([]string, 0, len(set))
	for key := range set {
		slice = append(slice, key)
	}
	sort.Strings(slice)
	return slice
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func contextSnippet(s string, start, end int) string {
	if start < 0 {
		start = 0
	}
	if end < start {
		end = start
	}
	left := start - 80
	if left < 0 {
		left = 0
	}
	right := end + 80
	if right > len(s) {
		right = len(s)
	}
	return strings.TrimSpace(strings.ReplaceAll(s[left:right], "\n", " "))
}
