package runner

import (
	"net/url"
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
	add := func(raw string) {
		raw = strings.TrimSpace(raw)
		if raw == "" || strings.HasPrefix(raw, "#") {
			return
		}
		if !strings.Contains(raw, "://") {
			raw = "https://" + raw
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			return
		}
		seed := strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host) + "/"
		if _, ok := seen[seed]; ok {
			return
		}
		seen[seed] = struct{}{}
		out = append(out, seed)
	}
	for _, q := range queries {
		add(q)
	}
	for _, u := range urls {
		if max > 0 && len(out) >= max {
			break
		}
		add(u)
	}
	return out
}
