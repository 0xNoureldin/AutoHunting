package commoncrawl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corpix/uarand"
	"github.com/cyinnove/logify"
)

type Source struct {
	apiKeys []string
}

func (s *Source) Name() string { return "commoncrawl" }

// Common Crawl does not require an API key for CDX.
func (s *Source) RequireAPIKey() bool { return true }

// Optional constructor (keep if your sources registry expects it)
func New(apiKeys []string) *Source {
	return &Source{apiKeys: apiKeys}
}

func (s *Source) Search(ctx context.Context, query string, client *http.Client) ([]string, error) {
	query = strings.TrimSpace(query)
	if query == "" {
		return nil, fmt.Errorf("empty query")
	}
	if client == nil {
		return nil, fmt.Errorf("nil http client")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	logify.Infof("commoncrawl: request started for %s", query)

	api, err := latestCDXAPI(ctx, client)
	if err != nil {
		api = fallbackCDXAPI()
		logify.Infof("commoncrawl: collinfo discovery failed for %s: %v; falling back to %s", query, err, api)
	}
	apis := []string{api}
	if fallback := fallbackCDXAPI(); fallback != api {
		apis = append(apis, fallback)
	}

	// Try both patterns:
	// 1) subdomains: *.example.com/*
	// 2) apex:       example.com/*
	// Many targets won't exist in CC; 404 should be treated as "no data".
	patterns := []string{
		"*." + query + "/*",
		query + "/*",
	}

	seen := make(map[string]struct{})
	out := make([]string, 0, 512)
	var lastSoftErr error
	success := false

	for _, api := range apis {
		apiSuccess := false
		for _, pat := range patterns {
			urls, err := cdxQueryWithRetry(ctx, client, api, pat)
			if err != nil {
				if isSoftErr(err) {
					lastSoftErr = err
					logify.Infof("commoncrawl: %s failed softly on %s: %v; trying next pattern", pat, api, err)
					continue
				}
				if len(out) > 0 {
					logify.Infof("commoncrawl: %s failed after partial results: %v", pat, err)
					break
				}
				return nil, err
			}
			success = true
			apiSuccess = true

			for _, u := range urls {
				u = strings.TrimSpace(u)
				if u == "" {
					continue
				}
				if _, ok := seen[u]; ok {
					continue
				}
				seen[u] = struct{}{}
				out = append(out, u)
			}
		}
		if len(out) > 0 {
			break
		}
		if !apiSuccess {
			logify.Infof("commoncrawl: no successful CDX response from %s; trying next index if available", api)
		}
	}

	if !success && lastSoftErr != nil {
		return nil, lastSoftErr
	}

	logify.Infof("commoncrawl: request completed for %s with %d urls", query, len(out))
	return out, nil
}

// -------------------- CDX querying + parsing --------------------

func cdxQueryWithRetry(ctx context.Context, client *http.Client, apiBase string, urlPattern string) ([]string, error) {
	const (
		maxRetries = 1
		baseDelay  = 500 * time.Millisecond
		maxDelay   = 5 * time.Second
	)

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if err := sleepExact(ctx, time.Duration(100+rand.Intn(200))*time.Millisecond); err != nil {
			return nil, err
		}

		urls, retry, err := cdxQueryOnce(ctx, client, apiBase, urlPattern)
		if err == nil && !retry {
			return urls, nil
		}
		if err != nil {
			lastErr = err
		}
		if !retry || attempt == maxRetries {
			if lastErr == nil {
				lastErr = fmt.Errorf("commoncrawl failed without explicit error")
			}
			return nil, lastErr
		}

		logify.Infof("commoncrawl: %s failed: %v; retrying attempt %d/%d", urlPattern, lastErr, attempt+2, maxRetries+1)
		if err := sleepBackoff(ctx, attempt, baseDelay, maxDelay); err != nil {
			return nil, err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("commoncrawl failed without explicit error")
	}
	return nil, lastErr
}

func cdxQueryOnce(ctx context.Context, client *http.Client, apiBase string, urlPattern string) ([]string, bool, error) {
	qv := url.Values{}
	qv.Set("url", urlPattern)
	qv.Set("output", "json")
	qv.Set("fl", "url")
	qv.Set("collapse", "urlkey")

	req, err := http.NewRequestWithContext(ctx, "GET", apiBase+"?"+qv.Encode(), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())

	resp, err := client.Do(req)
	if err != nil {
		// network errors are retryable
		if isRetryableNetErr(err) {
			return nil, true, err
		}
		return nil, false, err
	}
	defer resp.Body.Close()

	// 404 is common: "no records" (treat as empty, not error)
	if resp.StatusCode == http.StatusNotFound {
		return []string{}, false, nil
	}

	// Retryable statuses
	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
		// Honor Retry-After if present
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if d, ok := parseRetryAfter(ra); ok {
				_ = sleepExact(ctx, d)
			}
		}
		return nil, true, fmt.Errorf("commoncrawl retryable status %d", resp.StatusCode)
	}

	// Non-retryable non-2xx
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("commoncrawl non-2xx status %d", resp.StatusCode)
	}

	// Read a small prefix to detect format, then parse accordingly
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, true, fmt.Errorf("read body: %w", err)
	}

	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return []string{}, false, nil
	}

	// If it starts with '[' assume JSON array (some endpoints/params)
	if body[0] == '[' {
		return parseJSONArray(body)
	}

	// Otherwise assume JSON lines
	return parseJSONLines(body)
}

func parseJSONLines(b []byte) ([]string, bool, error) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 1024*1024), 10*1024*1024)

	type row struct {
		URL string `json:"url"`
	}

	out := make([]string, 0, 512)
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		var r row
		if err := json.Unmarshal(line, &r); err != nil {
			// If parsing fails, it could be a format mismatch; treat as retryable
			return nil, true, fmt.Errorf("parse json line: %w", err)
		}
		u := strings.TrimSpace(r.URL)
		if u != "" {
			out = append(out, u)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, true, fmt.Errorf("scanner: %w", err)
	}
	return out, false, nil
}

func parseJSONArray(b []byte) ([]string, bool, error) {
	// Sometimes array includes header-like objects; we only need url fields.
	type row struct {
		URL string `json:"url"`
	}
	var rows []row
	if err := json.Unmarshal(b, &rows); err != nil {
		// could be a different schema; retryable
		return nil, true, fmt.Errorf("parse json array: %w", err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		u := strings.TrimSpace(r.URL)
		if u != "" {
			out = append(out, u)
		}
	}
	return out, false, nil
}

// -------------------- CDX API discovery (cache success only) --------------------

type ccCollection struct {
	CDXAPI string `json:"cdx-api"`
}

func fallbackCDXAPI() string {
	return "https://index.commoncrawl.org/CC-MAIN-2026-04-index"
}

var (
	ccMu     sync.Mutex
	ccCached string
)

func latestCDXAPI(ctx context.Context, client *http.Client) (string, error) {
	ccMu.Lock()
	cached := ccCached
	ccMu.Unlock()
	if cached != "" {
		return cached, nil
	}

	api, err := fetchLatestCDXAPI(ctx, client)
	if err != nil {
		return "", err
	}

	ccMu.Lock()
	ccCached = api
	ccMu.Unlock()

	return api, nil
}

func fetchLatestCDXAPI(ctx context.Context, client *http.Client) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if client == nil {
		return "", fmt.Errorf("nil http client")
	}

	const (
		maxRetries = 1
		baseDelay  = 500 * time.Millisecond
		maxDelay   = 3 * time.Second
	)

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		api, retry, err := fetchLatestCDXAPIOnce(ctx, client)
		if err == nil && !retry {
			return api, nil
		}
		if err != nil {
			lastErr = err
		}
		if !retry || attempt == maxRetries {
			if lastErr == nil {
				lastErr = fmt.Errorf("commoncrawl collinfo failed without explicit error")
			}
			return "", lastErr
		}

		logify.Infof("commoncrawl: collinfo failed: %v; retrying attempt %d/%d", lastErr, attempt+2, maxRetries+1)
		if err := sleepBackoff(ctx, attempt, baseDelay, maxDelay); err != nil {
			return "", err
		}
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("commoncrawl collinfo failed without explicit error")
	}
	return "", lastErr
}

func fetchLatestCDXAPIOnce(ctx context.Context, client *http.Client) (string, bool, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "https://index.commoncrawl.org/collinfo.json", nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("User-Agent", uarand.GetRandom())

	resp, err := client.Do(req)
	if err != nil {
		if isRetryableNetErr(err) {
			return "", true, err
		}
		return "", false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if d, ok := parseRetryAfter(ra); ok {
				if err := sleepExact(ctx, d); err != nil {
					return "", false, err
				}
			}
		}
		return "", true, fmt.Errorf("commoncrawl collinfo status %d", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", false, fmt.Errorf("commoncrawl collinfo status %d", resp.StatusCode)
	}

	var collections []ccCollection
	if err := json.NewDecoder(resp.Body).Decode(&collections); err != nil {
		return "", true, fmt.Errorf("parse collinfo: %w", err)
	}
	if len(collections) == 0 || strings.TrimSpace(collections[0].CDXAPI) == "" {
		return "", false, fmt.Errorf("no collections returned")
	}

	return collections[0].CDXAPI, false, nil
}

// -------------------- helpers --------------------

func isRetryableNetErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "connection refused") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "tls handshake timeout") ||
		strings.Contains(s, "i/o timeout") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "temporary") ||
		strings.Contains(s, "dial tcp") ||
		strings.Contains(s, "context deadline exceeded") ||
		strings.Contains(s, "no such host") ||
		strings.Contains(s, "eof")
}

// isSoftErr is used to allow partial results when one pattern fails
func isSoftErr(err error) bool {
	if err == nil {
		return true
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "retryable") ||
		strings.Contains(s, "timeout") ||
		strings.Contains(s, "dial tcp") ||
		strings.Contains(s, "connection refused") ||
		strings.Contains(s, "eof") ||
		strings.Contains(s, "503") ||
		strings.Contains(s, "429")
}

func sleepBackoff(ctx context.Context, attempt int, base, max time.Duration) error {
	d := base * time.Duration(1<<attempt)
	if d > max {
		d = max
	}
	// jitter: 0.5x .. 1.5x
	j := time.Duration(rand.Int63n(int64(d)))
	sleep := (d / 2) + j
	return sleepExact(ctx, sleep)
}

func sleepExact(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	// seconds
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	// HTTP date
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}
