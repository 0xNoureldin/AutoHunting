package priority

import (
	"net/url"
	"sort"
	"strings"
)

type Ranked struct {
	URL    string
	Score  int
	Reason []string
}

var pathWeights = []struct {
	term   string
	weight int
	reason string
}{
	{"/admin", 100, "admin path"},
	{"/administrator", 100, "admin path"},
	{"/console", 90, "console path"},
	{"/dashboard", 85, "dashboard path"},
	{"/manage", 80, "management path"},
	{"/internal", 80, "internal path"},
	{"/private", 80, "private path"},
	{"/debug", 75, "debug path"},
	{"/api", 70, "api path"},
	{"/graphql", 70, "graphql path"},
	{"/login", 65, "auth path"},
	{"/signin", 65, "auth path"},
	{"/auth", 65, "auth path"},
	{"/oauth", 65, "oauth path"},
	{"/callback", 60, "callback path"},
	{"/upload", 55, "upload path"},
	{"/download", 55, "download path"},
	{"/backup", 50, "backup path"},
	{"/swagger", 50, "api docs"},
	{"/openapi", 50, "api docs"},
	{"/api-docs", 50, "api docs"},
}

var paramWeights = []struct {
	term   string
	weight int
	reason string
}{
	{"redirect", 35, "redirect parameter"},
	{"next", 30, "redirect parameter"},
	{"url", 30, "url parameter"},
	{"callback", 30, "callback parameter"},
	{"file", 30, "file parameter"},
	{"path", 30, "path parameter"},
	{"token", 25, "token parameter"},
	{"code", 20, "code parameter"},
	{"id", 15, "id parameter"},
}

func Rank(raw string) Ranked {
	r := Ranked{URL: raw}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return r
	}
	p := strings.ToLower(u.Path)
	q := strings.ToLower(u.RawQuery)
	for _, w := range pathWeights {
		if strings.HasPrefix(p, w.term) || strings.Contains(p, w.term+"/") {
			r.Score += w.weight
			r.Reason = append(r.Reason, w.reason)
		}
	}
	for _, w := range paramWeights {
		if strings.Contains(q, w.term+"=") || strings.Contains(q, w.term+"%5b") {
			r.Score += w.weight
			r.Reason = append(r.Reason, w.reason)
		}
	}
	if strings.HasSuffix(p, ".js") {
		r.Score += 20
		r.Reason = append(r.Reason, "javascript asset")
	}
	return r
}

func Sort(urls []string) []string {
	ranked := make([]Ranked, 0, len(urls))
	for _, u := range urls {
		ranked = append(ranked, Rank(u))
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].Score == ranked[j].Score {
			return ranked[i].URL < ranked[j].URL
		}
		return ranked[i].Score > ranked[j].Score
	})
	out := make([]string, 0, len(ranked))
	for _, r := range ranked {
		out = append(out, r.URL)
	}
	return out
}

func Interesting(urls []string, minScore int) []Ranked {
	out := make([]Ranked, 0)
	for _, u := range urls {
		r := Rank(u)
		if r.Score >= minScore {
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].URL < out[j].URL
		}
		return out[i].Score > out[j].Score
	})
	return out
}
