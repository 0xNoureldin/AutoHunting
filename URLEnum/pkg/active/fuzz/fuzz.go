// Package fuzz performs wordlist-based path/content discovery against a
// single seed URL: it captures a baseline response for a path that should
// not exist, then requests every wordlist entry concurrently and reports
// the ones whose response differs from that baseline (status, content
// length, or content type) -- i.e. paths that are likely real.
package fuzz

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cyinnove/logify"
)

type Options struct {
	Concurrency int           // concurrent path requests per seed
	Timeout     time.Duration // per-request timeout
	Method      string
}

func (o Options) withDefaults() Options {
	if o.Concurrency <= 0 {
		o.Concurrency = 20
	}
	if o.Timeout <= 0 {
		o.Timeout = 10 * time.Second
	}
	if o.Method == "" {
		o.Method = "GET"
	}
	return o
}

type fingerprint struct {
	StatusCode    int
	ContentLength int64
	ContentType   string
}

type baselineRange struct {
	statusMin, statusMax int
	lengthMin, lengthMax int64
	contentType          string // "" means "varied across samples, don't compare"
}

func (r baselineRange) inRange(fp fingerprint) bool {
	if fp.StatusCode < r.statusMin || fp.StatusCode > r.statusMax {
		return false
	}
	if fp.ContentLength < r.lengthMin || fp.ContentLength > r.lengthMax {
		return false
	}
	if r.contentType != "" && trimContentType(fp.ContentType) != r.contentType {
		return false
	}
	return true
}

// Enumerate fuzzes seed with each entry in wordlist as a path and returns
// the resulting URLs whose response differs from the baseline.
func Enumerate(ctx context.Context, seed string, wordlist []string, opts Options) ([]string, error) {
	opts = opts.withDefaults()

	base := normalizeBase(seed)
	if base == "" {
		return nil, fmt.Errorf("empty seed")
	}
	if len(wordlist) == 0 {
		return nil, nil
	}

	client := &http.Client{
		Timeout:   opts.Timeout,
		Transport: &http.Transport{MaxIdleConnsPerHost: opts.Concurrency},
	}

	baseline, err := captureBaseline(ctx, client, base, opts.Method)
	if err != nil {
		return nil, fmt.Errorf("baseline fingerprint for %s: %w", base, err)
	}

	jobs := make(chan string, len(wordlist))
	for _, w := range wordlist {
		w = strings.TrimSpace(w)
		if w != "" && !strings.HasPrefix(w, "#") {
			jobs <- w
		}
	}
	close(jobs)

	var (
		wg     sync.WaitGroup
		mu     sync.Mutex
		found  []string
		failed int
		tried  int
	)

	workers := opts.Concurrency
	if workers > len(wordlist) {
		workers = len(wordlist)
	}
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				target := buildURL(base, path)
				if target == "" {
					continue
				}

				fp, err := probe(ctx, client, target, opts.Method)
				mu.Lock()
				tried++
				if err != nil {
					failed++
					mu.Unlock()
					continue
				}
				if !baseline.inRange(fp) {
					found = append(found, target)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if failed > 0 {
		logify.Infof("fuzz: %s -> %d/%d interesting path(s) (%d/%d request(s) failed, e.g. network errors or a per-seed timeout)",
			base, len(found), len(wordlist), failed, tried)
	} else {
		logify.Infof("fuzz: %s -> %d/%d interesting path(s)", base, len(found), len(wordlist))
	}
	return found, nil
}

// captureBaseline requests a random, near-certainly-nonexistent path three
// times and ranges over status/length so that a target returning a
// consistent "soft 404" doesn't drown out every wordlist hit.
func captureBaseline(ctx context.Context, client *http.Client, base, method string) (baselineRange, error) {
	const samples = 3
	var fps []fingerprint

	for i := 0; i < samples; i++ {
		token, err := randomToken()
		if err != nil {
			return baselineRange{}, err
		}
		fp, err := probe(ctx, client, base+"/__nonexistent_"+token+"__", method)
		if err != nil {
			return baselineRange{}, err
		}
		fps = append(fps, fp)
	}

	r := baselineRange{
		statusMin: fps[0].StatusCode, statusMax: fps[0].StatusCode,
		lengthMin: fps[0].ContentLength, lengthMax: fps[0].ContentLength,
		contentType: trimContentType(fps[0].ContentType),
	}
	for _, fp := range fps[1:] {
		if fp.StatusCode < r.statusMin {
			r.statusMin = fp.StatusCode
		}
		if fp.StatusCode > r.statusMax {
			r.statusMax = fp.StatusCode
		}
		if fp.ContentLength < r.lengthMin {
			r.lengthMin = fp.ContentLength
		}
		if fp.ContentLength > r.lengthMax {
			r.lengthMax = fp.ContentLength
		}
		if trimContentType(fp.ContentType) != r.contentType {
			r.contentType = ""
		}
	}
	return r, nil
}

func probe(ctx context.Context, client *http.Client, target, method string) (fingerprint, error) {
	req, err := http.NewRequestWithContext(ctx, method, target, nil)
	if err != nil {
		return fingerprint{}, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return fingerprint{}, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	length := resp.ContentLength
	if length < 0 {
		length = int64(len(body))
	}
	return fingerprint{
		StatusCode:    resp.StatusCode,
		ContentLength: length,
		ContentType:   resp.Header.Get("Content-Type"),
	}, nil
}

func randomToken() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func trimContentType(s string) string {
	if idx := strings.Index(s, ";"); idx >= 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}

func normalizeBase(seed string) string {
	seed = strings.TrimSpace(seed)
	if seed == "" {
		return ""
	}
	if !strings.Contains(seed, "://") {
		seed = "https://" + seed
	}
	u, err := url.Parse(seed)
	if err != nil || u.Host == "" {
		return ""
	}
	u.Path, u.RawQuery, u.Fragment = "", "", ""
	return strings.TrimSuffix(u.String(), "/")
}

func buildURL(base, path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}
