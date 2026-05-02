package runner

import (
	"net/url"
	"path"
	"sort"
	"strings"
	"sync"

	"github.com/noureldinSAF/AutoHunting/URLEnum/internal/normalize"
	"github.com/noureldinSAF/AutoHunting/URLEnum/pkg/utils"
)

type resultStore struct {
	mu      sync.Mutex
	mode    normalize.Mode
	seen    map[string]string
	sources map[string]map[string]struct{}
}

func newResultStore(mode normalize.Mode) *resultStore {
	return &resultStore{
		mode:    mode,
		seen:    make(map[string]string),
		sources: make(map[string]map[string]struct{}),
	}
}

func (s *resultStore) Add(raw, source string) bool {
	raw = strings.TrimSpace(raw)
	if raw == "" || !utils.IsInformationalURL(raw) {
		return false
	}
	key := normalize.Key(raw, s.mode)
	if key == "" {
		return false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sources[key]; !ok {
		s.sources[key] = map[string]struct{}{}
	}
	s.sources[key][source] = struct{}{}
	if _, exists := s.seen[key]; exists {
		return false
	}
	s.seen[key] = canonicalForOutput(raw)
	return true
}

func (s *resultStore) List() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.seen))
	for _, u := range s.seen {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}

func (s *resultStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.seen)
}

func canonicalForOutput(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return raw
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	return u.String()
}

func parseDedupeMode(mode string) normalize.Mode {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "exact":
		return normalize.Exact
	case "path", "pathonly":
		return normalize.PathOnly
	default:
		return normalize.ParamAware
	}
}

func activeSeeds(queries []string, urls []string, max int) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(queries)+len(urls))

	addSeed := func(seed string) {
		if max > 0 && len(out) >= max {
			return
		}
		if _, ok := seen[seed]; ok {
			return
		}
		seen[seed] = struct{}{}
		out = append(out, seed)
	}

	parseCandidate := func(raw string) *url.URL {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return nil
		}
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return nil
		}
		scheme := strings.ToLower(u.Scheme)
		if scheme != "http" && scheme != "https" {
			return nil
		}
		u.Scheme = scheme
		u.Host = strings.ToLower(u.Host)
		u.Fragment = ""
		return u
	}

	addRoot := func(raw string) {
		u := parseCandidate(raw)
		if u == nil {
			return
		}
		addSeed(u.Scheme + "://" + u.Host + "/")
	}

	addHighValuePath := func(raw string) {
		u := parseCandidate(raw)
		if u == nil || isStaticSeedAsset(u.Path) || !isHighValueSeedPath(u.Path) {
			return
		}
		p := path.Clean(u.EscapedPath())
		if p == "." || p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		if p == "/" {
			return
		}
		addSeed(u.Scheme + "://" + u.Host + p)
	}

	for _, q := range queries {
		addRoot(q)
	}
	for _, u := range urls {
		addRoot(u)
	}
	for _, q := range queries {
		addHighValuePath(q)
	}
	for _, u := range urls {
		addHighValuePath(u)
	}
	return out
}

func isHighValueSeedPath(rawPath string) bool {
	p := strings.ToLower(rawPath)
	for _, term := range []string{
		"/admin",
		"/login",
		"/dashboard",
		"/api",
		"/graphql",
		"/swagger",
		"/openapi",
		"/console",
		"/internal",
		"/debug",
		"/oauth",
	} {
		if strings.HasPrefix(p, term) || strings.Contains(p, term+"/") || strings.HasSuffix(p, term) {
			return true
		}
	}
	return false
}

func isStaticSeedAsset(rawPath string) bool {
	ext := strings.ToLower(path.Ext(rawPath))
	switch ext {
	case ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip":
		return true
	default:
		return false
	}
}
