package runner

import (
	"net/url"
	"sort"
	"strings"
)

type scoredURL struct {
	url   string
	score int
}

func selectHeadlessSeeds(urls []string, limit int) []string {
	if limit <= 0 {
		limit = 100
	}
	seen := map[string]struct{}{}
	scored := make([]scoredURL, 0, len(urls))
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || u.Scheme == "" || u.Host == "" {
			continue
		}
		if !isHeadlessCandidate(u) {
			continue
		}
		seed := u.Scheme + "://" + strings.ToLower(u.Host) + u.Path
		if seed == "" || seed == u.Scheme+"://"+strings.ToLower(u.Host) {
			seed += "/"
		}
		if _, ok := seen[seed]; ok {
			continue
		}
		seen[seed] = struct{}{}
		scored = append(scored, scoredURL{url: seed, score: headlessScore(u)})
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score == scored[j].score {
			return len(scored[i].url) < len(scored[j].url)
		}
		return scored[i].score > scored[j].score
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}
	out := make([]string, 0, len(scored))
	for _, s := range scored {
		out = append(out, s.url)
	}
	return out
}

func isHeadlessCandidate(u *url.URL) bool {
	p := strings.ToLower(u.Path)
	if strings.Contains(p, "/static/") || strings.Contains(p, "/assets/") || strings.Contains(p, "/vendor/") {
		return false
	}
	for _, ext := range []string{".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".map", ".pdf", ".zip"} {
		if strings.HasSuffix(p, ext) {
			return false
		}
	}
	return true
}

func headlessScore(u *url.URL) int {
	p := strings.ToLower(u.Path)
	q := strings.ToLower(u.RawQuery)
	score := 0
	for _, hit := range []string{"/app", "/admin", "/login", "/signin", "/dashboard", "/portal", "/console", "/account", "/oauth", "/callback"} {
		if strings.Contains(p, hit) {
			score += 10
		}
	}
	for _, hit := range []string{"redirect", "return", "next", "url", "callback", "token", "code"} {
		if strings.Contains(q, hit) {
			score += 6
		}
	}
	if p == "/" || p == "" {
		score += 3
	}
	if strings.HasSuffix(p, ".html") || strings.HasSuffix(p, ".htm") || !strings.Contains(p[strings.LastIndex(p, "/")+1:], ".") {
		score += 4
	}
	return score
}
