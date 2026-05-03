package fuzz

import (
	"net/url"
	"sort"
	"strings"
)

var interestingParams = map[string]struct{}{
	"url": {}, "uri": {}, "next": {}, "return": {}, "returnurl": {}, "redirect": {}, "redirect_uri": {}, "callback": {},
	"file": {}, "path": {}, "page": {}, "template": {}, "include": {}, "download": {},
	"id": {}, "user": {}, "uid": {}, "account": {}, "order": {}, "invoice": {},
	"q": {}, "query": {}, "search": {}, "keyword": {},
	"token": {}, "code": {}, "state": {}, "session": {}, "jwt": {},
}

type Result struct {
	URL    string
	Params []string
	Score  int
}

func Generate(raw string, marker string) (Result, bool) {
	if marker == "" {
		marker = "FUZZ"
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return Result{}, false
	}
	q := u.Query()
	if len(q) == 0 {
		return Result{}, false
	}
	params := make([]string, 0, len(q))
	score := 0
	for k := range q {
		lk := strings.ToLower(k)
		params = append(params, k)
		if _, ok := interestingParams[lk]; ok {
			score += 10
		} else {
			score++
		}
		q.Set(k, marker)
	}
	sort.Strings(params)
	u.RawQuery = q.Encode()
	return Result{URL: u.String(), Params: params, Score: score}, true
}

func GenerateAll(urls []string, marker string, minScore int) []Result {
	seen := map[string]struct{}{}
	out := make([]Result, 0)
	for _, raw := range urls {
		r, ok := Generate(raw, marker)
		if !ok || r.Score < minScore {
			continue
		}
		if _, exists := seen[r.URL]; exists {
			continue
		}
		seen[r.URL] = struct{}{}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Score == out[j].Score {
			return out[i].URL < out[j].URL
		}
		return out[i].Score > out[j].Score
	})
	return out
}

func ParamNames(results []Result) []string {
	seen := map[string]struct{}{}
	for _, r := range results {
		for _, p := range r.Params {
			seen[p] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}
