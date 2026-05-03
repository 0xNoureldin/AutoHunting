package runner

import (
	"net/url"
	"regexp"
	"sort"
	"strings"
)

var endpointPatterns = []struct {
	kind string
	re   *regexp.Regexp
}{
	{"fetch", regexp.MustCompile(`(?is)\bfetch\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"axios", regexp.MustCompile(`(?is)\baxios\s*\.\s*(?:get|post|put|patch|delete|request)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"xhr", regexp.MustCompile(`(?is)\.open\s*\(\s*["'` + "`" + `](?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)["'` + "`" + `]\s*,\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"jquery", regexp.MustCompile(`(?is)\$\s*\.\s*(?:get|post|getJSON)\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"jquery", regexp.MustCompile(`(?is)\$\s*\.\s*ajax\s*\(\s*\{.*?\burl\s*:\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"import", regexp.MustCompile(`(?is)\bimport\s*\(\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]\s*\)`)},
	{"route", regexp.MustCompile(`(?is)\b(?:path|route|href|to)\s*:\s*["'` + "`" + `]([^"'` + "`" + `]+)["'` + "`" + `]`)},
	{"sourcemap", regexp.MustCompile(`(?i)sourceMappingURL=([^\s*]+)`)},
	{"graphql", regexp.MustCompile(`(?is)["'` + "`" + `]([^"'` + "`" + `]*(?:/graphql|graphql|gql)[^"'` + "`" + `]*)["'` + "`" + `]`)},
}

var fullURLRE = regexp.MustCompile(`(?i)\bhttps?://[a-z0-9][a-z0-9.-]*(?::\d{2,5})?(?:/[^\s"'<>)]*)?`)
var apiPathRE = regexp.MustCompile(`(?i)(?:^|[^a-z0-9_])(/(?:api|apis|v\d+|graphql|rest|rpc|oauth2?|auth|login|logout|token|sessions?|internal|admin|dashboard)(?:/[a-z0-9._~!$&'()*+,;=:@%-]+)*)`)

func ExtractEndpoints(sourceURL, body string, opts AnalyzeOptions) []EndpointFinding {
	opts = defaultOptions(opts)
	findings := make([]EndpointFinding, 0)
	add := func(kind, value string, start, end int) {
		value = cleanEndpoint(value)
		if value == "" || len(value) > 2048 {
			return
		}
		lowerValue := strings.ToLower(value)
		if kind == "graphql" && !strings.Contains(lowerValue, "graphql") && !strings.Contains(lowerValue, "/gql") {
			return
		}
		findings = append(findings, EndpointFinding{
			URL:     value,
			Kind:    kind,
			Source:  sourceURL,
			Context: contextSnippet(body, start, end),
		})
		if kind != "graphql" && (strings.Contains(lowerValue, "graphql") || strings.Contains(lowerValue, "/gql")) {
			findings = append(findings, EndpointFinding{
				URL:     value,
				Kind:    "graphql",
				Source:  sourceURL,
				Context: contextSnippet(body, start, end),
			})
		}
	}

	for _, loc := range fullURLRE.FindAllStringIndex(body, -1) {
		add("literal_url", body[loc[0]:loc[1]], loc[0], loc[1])
	}
	for _, match := range apiPathRE.FindAllStringSubmatchIndex(body, -1) {
		if len(match) >= 4 && match[2] >= 0 {
			add("relative_url", body[match[2]:match[3]], match[0], match[1])
		}
	}

	for _, lit := range scanStringLiterals(body, 1, 2048) {
		value := lit.Value
		if strings.Contains(value, "${") {
			if static := staticTemplatePrefix(value); static != "" {
				value = static
			}
		}
		switch {
		case isFullHTTPURL(value):
			add("literal_url", value, lit.Start, lit.End)
		case isRelativeEndpoint(value):
			add("relative_url", value, lit.Start, lit.End)
		case strings.Contains(strings.ToLower(value), "graphql") || strings.Contains(strings.ToLower(value), "gql"):
			add("graphql", value, lit.Start, lit.End)
		}
	}

	for _, p := range endpointPatterns {
		for _, match := range p.re.FindAllStringSubmatchIndex(body, -1) {
			if len(match) < 4 || match[2] < 0 {
				continue
			}
			add(p.kind, body[match[2]:match[3]], match[0], match[1])
		}
	}

	return limitEndpointFindings(dedupeEndpointFindings(findings), opts.MaxFindings)
}

func cleanEndpoint(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"'`+"`"+`<> )];,`)
	value = strings.ReplaceAll(value, `\/`, `/`)
	return value
}

func isFullHTTPURL(v string) bool {
	u, err := url.Parse(v)
	return err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != ""
}

func isRelativeEndpoint(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || strings.HasPrefix(v, "//") || strings.HasPrefix(v, "data:") || strings.HasPrefix(v, "javascript:") {
		return false
	}
	lv := strings.ToLower(v)
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		return strings.Contains(lv, "/api") ||
			strings.Contains(lv, "/v1") ||
			strings.Contains(lv, "/v2") ||
			strings.Contains(lv, "graphql") ||
			strings.Contains(lv, "admin") ||
			strings.Contains(lv, "login") ||
			strings.Contains(lv, "auth") ||
			strings.Contains(lv, "dashboard") ||
			strings.Contains(lv, ".js") ||
			strings.Contains(lv, ".map")
	}
	return false
}

func staticTemplatePrefix(v string) string {
	idx := strings.Index(v, "${")
	if idx < 0 {
		return ""
	}
	prefix := v[:idx]
	if prefix == "" {
		return ""
	}
	if !strings.HasSuffix(prefix, "/") {
		if slash := strings.LastIndex(prefix, "/"); slash >= 0 {
			prefix = prefix[:slash+1]
		}
	}
	if isRelativeEndpoint(prefix) || isFullHTTPURL(prefix) {
		return prefix
	}
	return ""
}

func dedupeEndpointFindings(in []EndpointFinding) []EndpointFinding {
	seen := map[string]EndpointFinding{}
	for _, f := range in {
		f.URL = cleanEndpoint(f.URL)
		if f.URL == "" {
			continue
		}
		key := f.Kind + "\x00" + f.Source + "\x00" + f.URL
		if _, ok := seen[key]; !ok {
			seen[key] = f
		}
	}
	out := make([]EndpointFinding, 0, len(seen))
	for _, f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].URL == out[j].URL {
			return out[i].Kind < out[j].Kind
		}
		return out[i].URL < out[j].URL
	})
	return out
}

func limitEndpointFindings(in []EndpointFinding, max int) []EndpointFinding {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max]
}
