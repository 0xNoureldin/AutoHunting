package crawl

import (
	"context" 
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"
	"github.com/corpix/uarand"
	"github.com/cyinnove/logify"
	"github.com/gocolly/colly/v2"
)

type Options struct {
	MaxDepth    int
	Parallelism int
	Timeout     time.Duration
	AllowQuery  bool // keep query params
}

// normalizeURL normalizes a URL by removing fragments and trailing slashes.
// It keeps query params if allowQuery is true.
func normalizeURL(u *url.URL, allowQuery bool) string {
	if u == nil {
		return ""
	}

	uu := *u
	uu.Fragment = ""

	path := uu.Path
	if path != "/" && strings.HasSuffix(path, "/") {
		path = strings.TrimSuffix(path, "/")
	}
	uu.Path = path

	normalized := uu.Scheme + "://" + uu.Host + uu.Path
	if allowQuery && uu.RawQuery != "" {
		normalized += "?" + uu.RawQuery
	}
	return normalized
}

func defaultOptions(opts *Options) Options {
	// FIX: do not reference runner variables here (opts.ActiveConcurrency/perTargetTimeout)
	if opts == nil {
		return Options{
			MaxDepth:    2,
			Parallelism: 4,
			Timeout:     15 * time.Second,
			AllowQuery:  true,
		}
	}

	o := *opts
	if o.MaxDepth <= 0 {
		o.MaxDepth = 2
	}
	if o.Parallelism <= 0 {
		o.Parallelism = 4
	}
	if o.Timeout <= 0 {
		o.Timeout = 15 * time.Second
	}
	// If you want default true even when caller didn't set it:
	// if !opts.AllowQuery { o.AllowQuery = true }
	return o
}

// hostAllowed checks whether hostname is allowed relative to the rootHost.
// If includeSubDomains is true, subdomains of rootHost are allowed.
func hostAllowed(host, rootHost string, includeSubDomains bool) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	rootHost = strings.ToLower(strings.TrimSpace(rootHost))

	if host == "" || rootHost == "" {
		return false
	}
	if host == rootHost {
		return true
	}
	if !includeSubDomains {
		return false
	}
	return strings.HasSuffix(host, "."+rootHost)
}

// Enumerate crawls starting from `start` and returns a unique list of normalized URLs visited/discovered.
func Enumerate(ctx context.Context, start string, includeSubDomains bool, opts *Options) ([]string, error) {
	logify.Infof("Starting crawl enumeration for %s (includeSubDomains=%v)", start, includeSubDomains)
	// NOTE: removed fmt.Println to avoid slowing down concurrent runs
	o := defaultOptions(opts)

	if strings.TrimSpace(start) == "" {
		return nil, errors.New("start URL is empty")
	}
	if !strings.HasPrefix(start, "http://") && !strings.HasPrefix(start, "https://") {
		start = "https://" + start
	}

	startURL, err := url.Parse(start)
	if err != nil {
		return nil, fmt.Errorf("parse start url: %w", err)
	}
	if startURL.Scheme == "" || startURL.Hostname() == "" {
		return nil, fmt.Errorf("invalid start url: %q", start)
	}

	rootHost := strings.ToLower(startURL.Hostname())

	c := colly.NewCollector(
		colly.MaxDepth(o.MaxDepth),
		colly.Async(true),
	)

	c.UserAgent = uarand.GetRandom()
	c.SetRequestTimeout(o.Timeout)

	_ = c.Limit(&colly.LimitRule{
		DomainGlob:  "*",
		Parallelism: o.Parallelism,
	})

	var (
		mu   sync.Mutex
		seen = make(map[string]struct{})
		out  = make([]string, 0, 256)
	)

	emit := func(u *url.URL) {
		if u == nil {
			return
		}
		if u.Scheme == "" || u.Host == "" {
			return
		}
		if !hostAllowed(u.Hostname(), rootHost, includeSubDomains) {
			return
		}

		normalized := normalizeURL(u, o.AllowQuery)
		if normalized == "" {
			return
		}

		mu.Lock()
		if _, exists := seen[normalized]; !exists {
			seen[normalized] = struct{}{}
			out = append(out, normalized)
		}
		mu.Unlock()
	}

	c.OnRequest(func(r *colly.Request) {
		// Respect ctx cancellation
		select {
		case <-ctx.Done():
			r.Abort()
			return
		default:
		}
		emit(r.URL)
	})

	c.OnHTML(`a[href], link[href], script[src], iframe[src], form[action]`, func(e *colly.HTMLElement) {
		// Respect ctx cancellation
		select {
		case <-ctx.Done():
			return
		default:
		}

		var raw string
		switch {
		case e.Attr("href") != "":
			raw = e.Attr("href")
		case e.Attr("src") != "":
			raw = e.Attr("src")
		case e.Attr("action") != "":
			raw = e.Attr("action")
		}
		if raw == "" {
			return
		}

		abs := e.Request.AbsoluteURL(raw)
		if abs == "" {
			return
		}

		u, err := url.Parse(abs)
		if err != nil {
			return
		}
		if u.Scheme == "" || u.Hostname() == "" {
			return
		}
		if !hostAllowed(u.Hostname(), rootHost, includeSubDomains) {
			return
		}

		emit(u)
		_ = c.Visit(u.String())
	})

	c.OnError(func(_ *colly.Response, _ error) {
		// Keep silent here; caller can log if needed.
	})

	if err := c.Visit(startURL.String()); err != nil {
		return nil, fmt.Errorf("visit start: %w", err)
	}

	c.Wait()

	if ctx.Err() != nil {
		return out, ctx.Err()
	}
	return out, nil
}
