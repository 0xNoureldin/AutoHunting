package fuzz

import (
	"sort"
	"strings"
)

type PayloadProfile struct {
	Category string
	Wordlist string
	Reason   string
}

var payloadRules = []struct {
	category string
	wordlist string
	reason   string
	terms    []string
}{
	{"redirect", "payloads/open-redirect.txt", "redirect-like parameter", []string{"url", "uri", "next", "return", "returnurl", "redirect", "redirect_uri", "callback", "continue", "dest", "destination"}},
	{"file", "payloads/lfi-path-traversal.txt", "file/path-like parameter", []string{"file", "path", "page", "template", "include", "download", "doc", "document", "folder", "dir"}},
	{"idor", "payloads/ids.txt", "object identifier parameter", []string{"id", "uid", "user", "userid", "account", "accountid", "order", "invoice", "org", "tenant"}},
	{"search", "payloads/search.txt", "search/query parameter", []string{"q", "query", "search", "keyword", "term", "filter", "sort"}},
	{"auth", "payloads/auth-tokens.txt", "auth/session parameter", []string{"token", "code", "state", "session", "jwt", "key", "apikey", "access_token", "refresh_token"}},
	{"ssrf", "payloads/urls.txt", "remote resource parameter", []string{"host", "domain", "site", "endpoint", "webhook", "feed", "image", "avatar", "proxy"}},
}

func RecommendPayloads(params []string) map[string][]PayloadProfile {
	out := map[string][]PayloadProfile{}
	for _, raw := range params {
		p := strings.ToLower(strings.TrimSpace(raw))
		if p == "" {
			continue
		}
		profiles := make([]PayloadProfile, 0)
		for _, r := range payloadRules {
			for _, term := range r.terms {
				if p == term || strings.Contains(p, term) {
					profiles = append(profiles, PayloadProfile{Category: r.category, Wordlist: r.wordlist, Reason: r.reason})
					break
				}
			}
		}
		if len(profiles) == 0 {
			profiles = append(profiles, PayloadProfile{Category: "generic", Wordlist: "payloads/generic.txt", Reason: "generic parameter"})
		}
		out[raw] = profiles
	}
	return out
}

func RecommendedWordlists(params []string) []string {
	seen := map[string]struct{}{}
	profiles := RecommendPayloads(params)
	for _, ps := range profiles {
		for _, p := range ps {
			seen[p.Wordlist] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for w := range seen {
		out = append(out, w)
	}
	sort.Strings(out)
	return out
}
