package webarchive

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/corpix/uarand"
	"github.com/cyinnove/logify"
)

type Source struct{}

func (s *Source) Name() string        { return "webarchive" }
func (s *Source) RequireAPIKey() bool { return false }

func (s *Source) Search(ctx context.Context, query string, client *http.Client) ([]string, error) {
	if strings.TrimSpace(query) == "" {
		return nil, fmt.Errorf("empty query")
	}
	if client == nil {
		return nil, fmt.Errorf("nil http client")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	cdx := fmt.Sprintf(
		"https://web.archive.org/cdx/search/cdx?url=*.%s/*&output=json&fl=original&collapse=urlkey",
		url.QueryEscape(query),
	)

	// Retry policy (tune)
	const (
		maxRetries = 1
		baseDelay  = 500 * time.Millisecond
		maxDelay   = 2 * time.Second
	)

	var lastErr error
	for attempt := 0; attempt <= maxRetries; attempt++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}

		if err := sleepExact(ctx, time.Duration(150+rand.Intn(350))*time.Millisecond); err != nil {
			return nil, err
		}

		req, err := http.NewRequestWithContext(ctx, "GET", cdx, nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("User-Agent", uarand.GetRandom())

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if attempt == maxRetries || !isRetryableNetErr(err) {
				return nil, err
			}
			if isContextDeadlineErr(err) {
				logify.Infof("webarchive: context deadline exceeded for %s; retrying attempt %d/%d", query, attempt+2, maxRetries+1)
			}
			if err := sleepBackoff(ctx, attempt, baseDelay, maxDelay); err != nil {
				return nil, err
			}
			continue
		}

		// Got HTTP response
		out, retry, err := handleWebArchiveResponse(ctx, resp, attempt, maxRetries, baseDelay, maxDelay)
		if err == nil && !retry {
			logify.Infof("webarchive: request completed for %s with %d urls", query, len(out))
			return out, nil
		}
		if err != nil {
			lastErr = err
		}
		if !retry {
			return nil, lastErr
		}
		// else retry
	}

	if lastErr == nil {
		lastErr = fmt.Errorf("webarchive: failed without explicit error")
	}
	return nil, lastErr
}

func handleWebArchiveResponse(
	ctx context.Context,
	resp *http.Response,
	attempt, maxRetries int,
	baseDelay, maxDelay time.Duration,
) ([]string, bool, error) {
	defer resp.Body.Close()

	// Retry on 429 and 5xx
	if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
		if attempt >= maxRetries {
			return nil, false, fmt.Errorf("webarchive returned status %d", resp.StatusCode)
		}

		// Honor Retry-After
		if ra := resp.Header.Get("Retry-After"); ra != "" {
			if d, ok := parseRetryAfter(ra); ok {
				if err := sleepExact(ctx, d); err != nil {
					return nil, false, err
				}
				return nil, true, fmt.Errorf("webarchive retry after status %d", resp.StatusCode)
			}
		}

		if err := sleepBackoff(ctx, attempt, baseDelay, maxDelay); err != nil {
			return nil, false, err
		}
		return nil, true, fmt.Errorf("webarchive retry after status %d", resp.StatusCode)
	}

	// Non-retryable non-2xx
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, false, fmt.Errorf("webarchive returned non-2xx status: %d", resp.StatusCode)
	}

	var rows [][]string
	if err := json.NewDecoder(resp.Body).Decode(&rows); err != nil {
		// JSON parse errors can be transient under load; optionally retry a couple times
		return nil, attempt < maxRetries, fmt.Errorf("failed to parse JSON: %w", err)
	}

	out := make([]string, 0, len(rows))
	for i := 1; i < len(rows); i++ {
		if len(rows[i]) == 0 {
			continue
		}
		u := strings.TrimSpace(rows[i][0])
		if u != "" {
			out = append(out, u)
		}
	}
	return out, false, nil
}

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
		strings.Contains(s, "no such host")
}

func isContextDeadlineErr(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "context deadline exceeded")
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

// Retry-After can be seconds or an HTTP date.
// We'll support seconds (most common). Date parsing can be added if needed.
func parseRetryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if secs, err := strconv.Atoi(v); err == nil && secs >= 0 {
		return time.Duration(secs) * time.Second, true
	}
	// Optional: parse HTTP-date formats
	if t, err := http.ParseTime(v); err == nil {
		d := time.Until(t)
		if d < 0 {
			d = 0
		}
		return d, true
	}
	return 0, false
}
