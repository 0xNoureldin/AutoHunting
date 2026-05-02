package priority

import (
	"net/url"
	"path"
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
	{"admin", 140, "admin path"},
	{"administrator", 140, "admin path"},
	{"console", 110, "console path"},
	{"dashboard", 105, "dashboard path"},
	{"api", 100, "api path"},
	{"auth", 95, "auth path"},
	{"signup", 90, "signup path"},
	{"register", 90, "signup path"},
	{"manage", 95, "management path"},
	{"management", 95, "management path"},
	{"internal", 95, "internal path"},
	{"private", 90, "private path"},
	{"debug", 90, "debug path"},
	{"graphql", 85, "graphql path"},
	{"swagger", 85, "api docs"},
	{"openapi", 85, "api docs"},
	{"api-docs", 85, "api docs"},
	{"login", 80, "auth path"},
	{"signin", 80, "auth path"},
	{"oauth", 75, "oauth path"},
	{"dev", 75, "development path"},
	{"devops", 75, "development path"},
	{"callback", 70, "callback path"},
	{"upload", 70, "upload path"},
	{"download", 65, "download path"},
	{"backup", 65, "backup path"},
	{"config", 55, "configuration path"},
	{"settings", 50, "settings path"},
}

var paramWeights = []struct {
	term   string
	weight int
	reason string
}{
	{"admin", 90, "admin parameter"},
	{"redirect", 85, "redirect parameter"},
	{"api", 80, "api parameter"},
	{"return", 75, "redirect parameter"},
	{"return_to", 75, "redirect parameter"},
	{"next", 75, "redirect parameter"},
	{"auth", 75, "auth parameter"},
	{"signup", 75, "signup parameter"},
	{"register", 75, "signup parameter"},
	{"url", 75, "url parameter"},
	{"callback", 70, "callback parameter"},
	{"file", 70, "file parameter"},
	{"path", 65, "path parameter"},
	{"token", 65, "token parameter"},
	{"access_token", 65, "token parameter"},
	{"dev", 60, "development parameter"},
	{"code", 55, "code parameter"},
	{"id", 45, "id parameter"},
}

var hostWeights = []struct {
	term   string
	weight int
	reason string
}{
	{"admin", 80, "admin host"},
	{"api", 70, "api host"},
	{"auth", 65, "auth host"},
	{"signup", 60, "signup host"},
	{"register", 60, "signup host"},
	{"dev", 55, "development host"},
	{"devops", 55, "development host"},
}

func Rank(raw string) Ranked {
	r := Ranked{URL: raw}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return r
	}
	p := strings.ToLower(u.Path)
	queryNames := make([]string, 0, len(u.Query()))
	for name := range u.Query() {
		queryNames = append(queryNames, strings.ToLower(name))
	}
	for _, w := range pathWeights {
		if pathHasPriorityTerm(p, w.term) {
			r.Score += w.weight
			r.Reason = append(r.Reason, w.reason)
		}
	}
	for _, w := range paramWeights {
		for _, name := range queryNames {
			if paramHasPriorityTerm(name, w.term) {
				r.Score += w.weight
				r.Reason = append(r.Reason, w.reason)
				break
			}
		}
	}
	for _, w := range hostWeights {
		if hostHasPriorityTerm(u.Host, w.term) {
			r.Score += w.weight
			r.Reason = append(r.Reason, w.reason)
		}
	}
	if isJavaScriptPath(p) {
		r.Score += 5
		r.Reason = append(r.Reason, "javascript asset")
	}
	return r
}

func pathHasPriorityTerm(rawPath string, term string) bool {
	term = strings.Trim(strings.ToLower(term), "/")
	if term == "" {
		return false
	}
	for _, segment := range strings.Split(strings.ToLower(rawPath), "/") {
		if segment == "" {
			continue
		}
		if segmentMatchesPriorityTerm(segment, term) {
			return true
		}
		base := strings.TrimSuffix(segment, path.Ext(segment))
		if base != segment && segmentMatchesPriorityTerm(base, term) {
			return true
		}
	}
	return false
}

func segmentMatchesPriorityTerm(segment, term string) bool {
	if segment == term {
		return true
	}
	if len(segment) > len(term) && strings.HasPrefix(segment, term) {
		next := segment[len(term)]
		if next >= '0' && next <= '9' {
			return true
		}
		if len(term) >= 4 {
			return true
		}
	}
	for _, sep := range []string{"-", "_", ".", "~"} {
		if strings.HasPrefix(segment, term+sep) || strings.HasSuffix(segment, sep+term) || strings.Contains(segment, sep+term+sep) {
			return true
		}
	}
	return false
}

func paramHasPriorityTerm(name, term string) bool {
	tokens := identifierTokens(name)
	name = strings.ToLower(strings.TrimSpace(name))
	term = strings.ToLower(term)
	for _, token := range tokens {
		if token == term {
			return true
		}
	}
	if len(term) >= 4 && strings.Contains(name, term) {
		return true
	}
	compactName := strings.NewReplacer("-", "", "_", "", ".", "").Replace(name)
	compactTerm := strings.NewReplacer("-", "", "_", "", ".", "").Replace(term)
	if compactTerm == "" {
		return false
	}
	if len(term) <= 3 {
		if term != "api" {
			return compactName == compactTerm
		}
		for _, allowed := range []string{"api", "apikey", "apitoken", "apiurl", "apiendpoint", "apiversion"} {
			if strings.HasPrefix(compactName, allowed) {
				return true
			}
		}
		return false
	}
	return strings.Contains(compactName, compactTerm)
}

func hostHasPriorityTerm(host, term string) bool {
	host = strings.ToLower(host)
	for _, part := range strings.Split(host, ".") {
		if segmentMatchesPriorityTerm(part, term) {
			return true
		}
	}
	return false
}

func identifierTokens(s string) []string {
	var tokens []string
	var b strings.Builder
	var prev rune
	flush := func() {
		if b.Len() == 0 {
			return
		}
		tokens = append(tokens, strings.ToLower(b.String()))
		b.Reset()
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			if b.Len() > 0 && prev >= 'a' && prev <= 'z' && r >= 'A' && r <= 'Z' {
				flush()
			}
			b.WriteRune(r)
			prev = r
		default:
			flush()
			prev = 0
		}
	}
	flush()
	return tokens
}

func isJavaScriptPath(rawPath string) bool {
	switch strings.ToLower(path.Ext(rawPath)) {
	case ".js", ".mjs", ".cjs":
		return true
	default:
		return false
	}
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
