package jsparse

import (
	"net/url"
	"regexp"
	"strings"
)

type Finding struct {
	Value string
	Kind  string
}

var deepPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"fetch", regexp.MustCompile(`(?i)fetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"axios", regexp.MustCompile(`(?i)axios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"xhr", regexp.MustCompile(`(?i)\.open\s*\(\s*["'` + "`" + `](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'` + "`" + `]\s*,\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"import", regexp.MustCompile(`(?i)import\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]\s*\)`)},
	{"route", regexp.MustCompile(`(?i)(?:path|route|url|href|to)\s*:\s*["'` + "`" + `](/[^"'` + "`" + `\s]+)["'` + "`" + `]`)},
	{"graphql", regexp.MustCompile(`(?i)["'` + "`" + `]([^"'` + "`" + `]*(?:graphql|gql)[^"'` + "`" + `]*)["'` + "`" + `]`)},
	{"sourcemap", regexp.MustCompile(`(?i)sourceMappingURL=([^\s]+)`)},
}

func DeepAnalyze(body string) []Finding {
	seen := map[string]struct{}{}
	out := make([]Finding, 0)
	add := func(kind, value string) {
		value = strings.TrimSpace(value)
		if value == "" || len(value) > 2048 {
			return
		}
		key := kind + "\x00" + value
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, Finding{Value: value, Kind: kind})
	}

	for _, p := range deepPatterns {
		for _, m := range p.re.FindAllStringSubmatch(body, -1) {
			if len(m) > 1 {
				add(p.kind, m[1])
			}
		}
	}
	for _, ep := range ExtractEndpoints(body) {
		add("literal", ep)
	}
	return out
}

func ResolveFindings(baseURL string, findings []Finding) []string {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		raw := strings.TrimSpace(f.Value)
		if raw == "" || strings.HasPrefix(raw, "data:") || strings.HasPrefix(raw, "javascript:") {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(u).String()
		if _, ok := seen[abs]; ok {
			continue
		}
		seen[abs] = struct{}{}
		out = append(out, abs)
	}
	return out
}
