package runner

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cyinnove/logify"
)

const userAgent = "Mozilla/5.0 (compatible; jsAnalyzer/1.0; +https://github.com/noureldinSAF/AutoHunting)"

type Fetcher struct {
	client *http.Client
	opts   AnalyzeOptions
}

func NewFetcher(opts AnalyzeOptions) *Fetcher {
	opts = defaultOptions(opts)
	return &Fetcher{
		opts: opts,
		client: &http.Client{
			Timeout: opts.Timeout,
			Transport: &http.Transport{
				TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
				Proxy:               http.ProxyFromEnvironment,
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     30 * time.Second,
			},
		},
	}
}

func (f *Fetcher) Fetch(rawURL string) (FetchResult, error) {
	u, err := validateHTTPURL(rawURL)
	if err != nil {
		return FetchResult{}, err
	}

	attempts := f.opts.Retries + 1
	var lastErr error
	for attempt := 1; attempt <= attempts; attempt++ {
		result, retryAfter, err := f.fetchOnce(u)
		if err == nil {
			logify.Infof("jsAnalyzer: fetched %s successfully, size=%d bytes", u, len(result.Body))
			return result, nil
		}
		lastErr = err
		if !isRetryableFetchError(err) || attempt == attempts {
			break
		}

		delay := retryAfter
		if delay <= 0 {
			delay = retryDelay(attempt)
		}
		logify.Infof("jsAnalyzer: retrying %s after %v (attempt %d/%d)", u, err, attempt+1, attempts)
		if sleepErr := sleepContext(context.Background(), delay); sleepErr != nil {
			return FetchResult{}, sleepErr
		}
	}

	return FetchResult{}, lastErr
}

func (f *Fetcher) fetchOnce(rawURL string) (FetchResult, time.Duration, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, rawURL, nil)
	if err != nil {
		return FetchResult{}, 0, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/javascript,text/javascript,application/x-javascript,text/plain,*/*;q=0.8")

	resp, err := f.client.Do(req)
	if err != nil {
		return FetchResult{}, 0, err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
		return FetchResult{}, parseRetryAfter(resp.Header.Get("Retry-After")), fmt.Errorf("status %d", resp.StatusCode)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return FetchResult{}, 0, fmt.Errorf("non-2xx status %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if f.opts.StrictJS && !isJavaScriptContentType(contentType) {
		return FetchResult{}, 0, fmt.Errorf("strict-js rejected content-type %q", contentType)
	}

	body, err := readLimited(resp.Body, f.opts.MaxSize)
	if err != nil {
		return FetchResult{}, 0, err
	}
	if !f.opts.StrictJS && !isJavaScriptContentType(contentType) && !isTextLikeContentType(contentType) && looksBinary(body) {
		return FetchResult{}, 0, fmt.Errorf("response looks binary, content-type %q", contentType)
	}

	return FetchResult{
		URL:         rawURL,
		Body:        body,
		ContentType: contentType,
		StatusCode:  resp.StatusCode,
	}, 0, nil
}

func validateHTTPURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported URL scheme %q", u.Scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("URL host is required")
	}
	return u.String(), nil
}

func readLimited(r io.Reader, max int64) ([]byte, error) {
	if max <= 0 {
		max = 5 * 1024 * 1024
	}
	lr := &io.LimitedReader{R: r, N: max + 1}
	body, err := io.ReadAll(lr)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, fmt.Errorf("response body exceeds max-size %d bytes", max)
	}
	return body, nil
}

func isJavaScriptContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "ecmascript") ||
		strings.Contains(ct, "application/x-javascript")
}

func isTextLikeContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return ct == "" ||
		strings.Contains(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml")
}

func looksBinary(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	limit := len(body)
	if limit > 512 {
		limit = 512
	}
	for _, b := range body[:limit] {
		if b == 0 {
			return true
		}
	}
	return false
}

func isRetryableFetchError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	for _, token := range []string{
		"context deadline exceeded",
		"i/o timeout",
		"tls handshake timeout",
		"connection reset",
		"connection refused",
		"temporary",
		"eof",
		"status 429",
		"status 500",
		"status 502",
		"status 503",
		"status 504",
	} {
		if strings.Contains(msg, token) {
			return true
		}
	}
	return false
}

func retryDelay(attempt int) time.Duration {
	base := 300 * time.Millisecond
	maxDelay := 5 * time.Second
	delay := base * time.Duration(1<<(attempt-1))
	if delay > maxDelay {
		delay = maxDelay
	}
	jitter := time.Duration(rand.Int63n(int64(delay / 2)))
	return delay + jitter
}

func sleepContext(ctx context.Context, d time.Duration) error {
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

func parseRetryAfter(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil {
		if d := time.Until(t); d > 0 {
			return d
		}
	}
	return 0
}
