package runner

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/corpix/uarand"
	"github.com/cyinnove/logify"
	"github.com/ditashi/jsbeautifier-go/jsbeautifier"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

func getClient(opts AnalyzeOptions) *http.Client {
	return &http.Client{
		Timeout: opts.Timeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
}

func GetContent(url string, opts AnalyzeOptions) (string, error) {
	client := getClient(opts)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())

	resp, err := client.Do(req)
	if err != nil {
		logify.Errorf("HTTP request failed for %s: %v", url, err)
		return "", err
	}
	defer resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), opts.Timeout)
	defer cancel()

	bodyChan := make(chan []byte)
	errChan := make(chan error)

	go func() {
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			errChan <- err
			return
		}
		bodyChan <- body
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("timeout while reading response from %s", url)
	case err := <-errChan:
		logify.Errorf("Error reading response body from %s: %v", url, err)
		return "", err
	case body := <-bodyChan:
		return string(body), nil
	}
}

func BeatifyJS(source string, opts AnalyzeOptions) string {
	const MaxBeautifySize = 5 * 1024 * 1024 // 5 MB
	if len(source) > MaxBeautifySize {
		return source
	}

	prettryChan := make(chan string, 1)
	errChan := make(chan string, 1)
	go func() {
		opts := jsbeautifier.DefaultOptions()
		pretty, err := jsbeautifier.Beautify(&source, opts)
		if err != nil {
			errChan <- source
			return
		}
		prettryChan <- pretty
	}()

	timeout := time.NewTimer(opts.Timeout)

	defer timeout.Stop()

	select {
	case pretty := <-prettryChan:
		return pretty
	case <-timeout.C:
		return source
	case err := <-errChan:
		logify.Errorf("Error beautifying JS content: %v", err)
		return source
	}

}

func setToSlice(set map[string]struct{}) []string {
	slice := make([]string, 0, len(set))
	for key := range set {
		slice = append(slice, key)
	}
	return slice
}

// secretPatterns is compiled exactly once at package init, mirroring the other
// regexes in vars.go. LoadSecretPatterns used to call regexp.MustCompile for
// every pattern on every single JS file scan (ScanJSURL -> AnalyzeJSContent ->
// FindSecrets -> LoadSecretPatterns), which is wasted CPU work repeated once
// per file for the lifetime of a scan instead of once for the whole process.
var secretPatterns = []SecretPattern{
	// --- Cloud providers ---
	{Name: "AWS Access Key ID", Re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{Name: "AWS Temporary Access Key ID", Re: regexp.MustCompile(`ASIA[0-9A-Z]{16}`)},
	{Name: "AWS Secret Key", Re: regexp.MustCompile(`(?i)aws(?:.{0,20})?(?:secret)?(?:.{0,20})?['"]([0-9a-zA-Z/+]{40})['"]`)},
	{Name: "Google API Key", Re: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`)},
	{Name: "Google OAuth Access Token", Re: regexp.MustCompile(`ya29\.[0-9A-Za-z\-_]+`)},
	{Name: "Azure Storage Account Key", Re: regexp.MustCompile(`AccountKey=[A-Za-z0-9+/]{86}==`)},
	{Name: "DigitalOcean Personal Access Token", Re: regexp.MustCompile(`dop_v1_[a-f0-9]{64}`)},

	// --- Source control / package registries ---
	{Name: "GitHub Personal Access Token", Re: regexp.MustCompile(`ghp_[0-9A-Za-z]{36}`)},
	{Name: "GitHub Fine-Grained PAT", Re: regexp.MustCompile(`github_pat_[0-9A-Za-z_]{20,}`)},
	{Name: "GitHub OAuth/App Token", Re: regexp.MustCompile(`gh[ours]_[0-9A-Za-z]{36}`)},
	{Name: "GitLab Personal Access Token", Re: regexp.MustCompile(`glpat-[0-9A-Za-z\-_]{20}`)},
	{Name: "npm Access Token", Re: regexp.MustCompile(`npm_[0-9A-Za-z]{36}`)},

	// --- Payments ---
	{Name: "Stripe Secret Key", Re: regexp.MustCompile(`sk_(?:live|test)_[0-9A-Za-z]{16,64}`)},
	{Name: "Stripe Restricted Key", Re: regexp.MustCompile(`rk_(?:live|test)_[0-9A-Za-z]{16,64}`)},
	{Name: "Square Access Token", Re: regexp.MustCompile(`sq0atp-[0-9A-Za-z\-_]{22}`)},
	{Name: "Square OAuth Secret", Re: regexp.MustCompile(`sq0csp-[0-9A-Za-z\-_]{43}`)},
	{Name: "PayPal Braintree Access Token", Re: regexp.MustCompile(`access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`)},

	// --- Messaging / comms ---
	{Name: "Slack Token", Re: regexp.MustCompile(`xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}`)},
	{Name: "Slack Webhook URL", Re: regexp.MustCompile(`https://hooks\.slack\.com/services/T[0-9A-Za-z]{6,12}/B[0-9A-Za-z]{6,12}/[0-9A-Za-z]{16,32}`)},
	{Name: "SendGrid API Key", Re: regexp.MustCompile(`SG\.[0-9A-Za-z\-_]{20,24}\.[0-9A-Za-z\-_]{38,45}`)},
	{Name: "Mailgun API Key", Re: regexp.MustCompile(`key-[0-9a-f]{32}`)},
	{Name: "Facebook Access Token", Re: regexp.MustCompile(`EAACEdEose0cBA[0-9A-Za-z]+`)},
	{Name: "Discord Bot Token", Re: regexp.MustCompile(`[MN][a-zA-Z0-9_-]{23,25}\.[a-zA-Z0-9_-]{6}\.[a-zA-Z0-9_-]{27,40}`)},

	// --- Generic / structural ---
	{Name: "JWT", Re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{Name: "Private Key Block", Re: regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`)},
	{Name: "Credentials in URL", Re: regexp.MustCompile(`[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[A-Za-z0-9._%+-]{1,64}:[^\s"'@/]{3,64}@[A-Za-z0-9.-]+`)},
	{Name: "Generic API Key/Secret", Re: regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|private[_-]?key|password|passwd)\s*[:=]\s*['"]([A-Za-z0-9_\-.+/=]{12,100})['"]`)},
}

func LoadSecretPatterns() ([]SecretPattern, error) {
	return secretPatterns, nil
}

type MultiError struct{ Errs []error }

func (m MultiError) Error() string { return m.Errs[0].Error() } // simple

func ScanJSURLs(urls []string, concurrency int, opts AnalyzeOptions) ([]ScanResult, error) {
	urls = sanitizeURLs(urls)
	if len(urls) == 0 {
		return []ScanResult{}, fmt.Errorf("no URLs provided")
	}
	if concurrency <= 0 {
		concurrency = 1
	}

	results := make([]ScanResult, len(urls))
	ok := make([]bool, len(urls))
	errs := make(chan error, len(urls))

	var wg sync.WaitGroup
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex

	for i, u := range urls {
		i, u := i, strings.TrimSpace(u)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if u == "" {
				errs <- fmt.Errorf("empty url at index %d", i)
				return
			}

			res, err := ScanJSURL(u, opts)
			if err != nil {
				errs <- fmt.Errorf("error scanning %s: %w", u, err)
				return
			}

			mu.Lock()
			results[i] = res
			ok[i] = true
			mu.Unlock()
		}()
	}

	wg.Wait()
	close(errs)

	var allErrs []error
	for e := range errs {
		allErrs = append(allErrs, e)
	}

	// Keep only successful results (so you don’t get zero-value entries).
	final := make([]ScanResult, 0, len(urls))
	for i := range results {
		if ok[i] {
			final = append(final, results[i])
		}
	}

	if len(allErrs) > 0 {
		return final, MultiError{Errs: allErrs} // partial results + error
	}
	return final, nil
}

func ScanJSURL(url string, opts AnalyzeOptions) (ScanResult, error) {
	// Placeholder for actual scanning logic
	body, err := GetContent(url, opts)
	if err != nil {
		logify.Errorf("Failed to scan JS file at %s: %v", url, err)
		return ScanResult{}, err
	}

	res, err := AnalyzeJSContent(body, opts)
	if err != nil {
		logify.Errorf("Failed to analyze JS content from %s: %v", url, err)
		return ScanResult{}, err
	}

	res.URL = url
	return res, nil
}

func EncodeResults(results []ScanResult) ([]byte, error) {
	// Placeholder for actual encoding logic
	return json.MarshalIndent(results, "", "  ")
}

// GroupSecretsByValue collapses per-URL secret matches into one entry per
// distinct (pattern, value) pair, listing every URL it was found in. URLs
// with no secret matches contribute nothing and are dropped entirely,
// rather than appearing as an empty/URL-only entry.
func GroupSecretsByValue(results []ScanResult) []SecretGroup {
	type key struct{ pattern, value string }
	index := make(map[key]int)
	groups := []SecretGroup{}

	for _, r := range results {
		for _, m := range r.SecretMatches {
			k := key{m.PatternName, m.Value}
			if i, ok := index[k]; ok {
				groups[i].URLs = append(groups[i].URLs, r.URL)
				continue
			}
			index[k] = len(groups)
			groups = append(groups, SecretGroup{
				Pattern: m.PatternName,
				Value:   m.Value,
				URLs:    []string{r.URL},
			})
		}
	}
	return groups
}

func EncodeSecretGroups(groups []SecretGroup) ([]byte, error) {
	return json.MarshalIndent(groups, "", "  ")
}

func ReadInputFromFile(file string) ([]string, error) {

	fileData, err := os.ReadFile(file)
	if err != nil {
		return []string{}, err
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
		if u == "" {
			continue
		}
		// Optional: skip non-http(s)
		if !(strings.HasPrefix(u, "http://") || strings.HasPrefix(u, "https://")) {
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
	// all false by default
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
