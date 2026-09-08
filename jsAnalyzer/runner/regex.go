package runner

import (
	"github.com/cyinnove/logify"
	"strings"
	"math"
	//"regexp"
	
)	

func AnalyzeJSContent(content string, opts AnalyzeOptions) (ScanResult, error) {
	pretty := BeatifyJS(content, opts)

	subdomains := make(map[string]struct{})
	clouds := make(map[string]struct{})
	endpoints := make(map[string]struct{})
	params := make(map[string]struct{})
	npm := make(map[string]struct{})

	secretSet := make(map[string]struct{})
	var secretMatches []*SecretMatch

	if opts.Subdomains {
		for _, s := range SubdomainRegex.FindAllString(pretty, -1) {
			subdomains[s] = struct{}{}
		}
	}

	if opts.Cloud {
		for _, c := range CloudBucketRegex.FindAllString(pretty, -1) {
			clouds[c] = struct{}{}
		}
	}

	if opts.Endpoints {
		for _, e := range EndpointRegex.FindAllString(pretty, -1) {
			e = strings.TrimSpace(e)
			if e != "" {
				endpoints[e] = struct{}{}
			}
		}
	}

	if opts.Params {
		for _, p := range ParameterRegex.FindAllString(pretty, -1) {
			p = strings.TrimSpace(p)
			if p != "" {
				params[p] = struct{}{}
			}
		}
	}

	if opts.Npm {
		if subs := NodeModulesRegex.FindAllStringSubmatch(pretty, -1); len(subs) > 0 {
			for _, pkg := range subs {
				if len(pkg) > 1 && pkg[1] != "" {
					npm[pkg[1]] = struct{}{}
				}
			}
		}
	}

	if opts.Secrets {
		secretMatches, secretSet = FindSecrets(pretty)
	}

	results := ScanResult{
		Subdomains:     setToSlice(subdomains),
		CloudBuckets:   setToSlice(clouds),
		Endpoints:      setToSlice(endpoints),
		Parameters:     setToSlice(params),
		NpmPackages:    setToSlice(npm),
		Secrets:        secretSet,
		SecretMatches:  secretMatches,
	}

	logify.Infof(
		"Scan complete: subdomains=%d cloud=%d endpoints=%d params=%d npm=%d secrets=%d (opts: %+v)",
		len(results.Subdomains), len(results.CloudBuckets), len(results.Endpoints),
		len(results.Parameters), len(results.NpmPackages), len(results.Secrets), opts,
	)

	return results, nil
}



// secretKeywords are case-insensitive: real-world JS uses every casing
// convention for identifiers (apiKey, ApiKey, API_KEY, api_key, ...), and a
// case-sensitive check silently skips whole classes of PascalCase/CONST_CASE
// code.
var secretKeywords = []string{
	"key", "token", "secret", "pass", "auth", "bearer", "api",
	"credential", "private",
}

// secretMarkers are fixed-case vendor prefixes where casing is part of the
// spec (a real AWS key is always "AKIA", never "akia"), so keeping them
// case-sensitive avoids diluting the pre-filter with unrelated matches.
var secretMarkers = []string{
	"x-", "AKIA", "ASIA", "-----BEGIN", "sk_", "rk_", "AIza", "ya29.",
	"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-",
	"npm_", "xoxb-", "xoxp-", "dop_v1_", "sq0atp-", "sq0csp-", "SG.",
	"key-", "EAACEdEose0cBA", "eyJ",
}

// extractSecretCandidateWindows pulls smaller chunks where secrets usually appear.
// This reduces false positives in massive/minified code and speeds up scanning.
func extractSecretCandidateWindows(s string) []string {
	const maxWin = 4000
	var out []string

	lines := strings.Split(s, "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		if l == "" {
			continue
		}

		matched := false
		lower := strings.ToLower(l)
		for _, kw := range secretKeywords {
			if strings.Contains(lower, kw) {
				matched = true
				break
			}
		}
		if !matched {
			for _, m := range secretMarkers {
				if strings.Contains(l, m) {
					matched = true
					break
				}
			}
		}

		if matched {
			if len(l) > maxWin {
				l = l[:maxWin]
			}
			out = append(out, l)
		}
	}

	// Add extracted string literals without lookahead/lookbehind.
	out = append(out, extractStringLiteralsNoLookahead(s, 6, 600, maxWin)...)

	if len(out) == 0 {
		if len(s) > 200000 {
			out = append(out, s[:200000])
		} else {
			out = append(out, s)
		}
	}
	return out
}

// Extract "..." / '...' / `...` string literals using a small scanner.
// This avoids unsupported regex features in Go.
func extractStringLiteralsNoLookahead(s string, minLen, maxLen, maxWin int) []string {
	var out []string
	n := len(s)

	for i := 0; i < n; i++ {
		q := s[i]
		if q != '"' && q != '\'' && q != '`' {
			continue
		}

		start := i
		i++ // move past quote
		esc := false

		for i < n {
			c := s[i]

			if esc {
				esc = false
				i++
				continue
			}
			if c == '\\' {
				esc = true
				i++
				continue
			}
			if c == q {
				// found end quote
				lit := s[start : i+1]
				innerLen := (i + 1) - start - 2
				if innerLen >= minLen && innerLen <= maxLen {
					if len(lit) > maxWin {
						lit = lit[:maxWin]
					}
					out = append(out, lit)
				}
				break
			}

			// Stop if newline inside ' or " literal (backticks can include newlines, but we keep it simple)
			if (q == '"' || q == '\'') && (c == '\n' || c == '\r') {
				break
			}

			i++
		}
	}
	return out
}

// pickBestSecretGroup returns the most likely "secret value" from a regex match.
// If the regex has capture groups, prefer the last non-empty group.
// Otherwise fall back to the full match.
func pickBestSecretGroup(submatch []string) string {
	if len(submatch) == 0 {
		return ""
	}
	// submatch[0] is whole match; later entries are capture groups.
	for i := len(submatch) - 1; i >= 1; i-- {
		if strings.TrimSpace(submatch[i]) != "" {
			return submatch[i]
		}
	}
	return submatch[0]
}

// isPlausibleSecret filters obvious junk and common false positives.
func isPlausibleSecret(v string) bool {
	if v == "" {
		return false
	}
	if len(v) < 8 || len(v) > 1000 {
		return false
	}

	lv := strings.ToLower(v)

	// Common placeholders / test values / non-secrets
	bad := []string{
		"changeme", "change-me", "your_api_key", "your-api-key", "apikey", "api_key_here",
		"example", "sample", "dummy", "test", "placeholder", "xxxx", "1111", "0000",
		"null", "undefined", "true", "false",
	}
	for _, b := range bad {
		if strings.Contains(lv, b) {
			return false
		}
	}

	// Avoid matching full URLs as secrets
	if strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") {
		return false
	}

	// Avoid extremely repetitive strings
	if isMostlyOneChar(v) {
		return false
	}

	return true
}

func normalizeSecret(v string) string {
	v = strings.TrimSpace(v)

	// Strip surrounding quotes/backticks if present
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') ||
			(v[0] == '\'' && v[len(v)-1] == '\'') ||
			(v[0] == '`' && v[len(v)-1] == '`') {
			v = v[1 : len(v)-1]
			v = strings.TrimSpace(v)
		}
	}

	// Remove trailing punctuation often captured by regex
	v = strings.TrimRight(v, `,;:)]}>"'`)

	// Hard cap to avoid huge blobs in output
	if len(v) > 300 {
		v = v[:300] + "...(truncated)"
	}
	return v
}

// passesEntropyHeuristic attempts to reduce false positives.
// - Accept PEM blocks and known prefixes even if entropy calc is weird.
// - Otherwise require moderate entropy + enough variety.
func passesEntropyHeuristic(v string) bool {
	lv := strings.ToLower(v)

	// Always accept these shapes (they’re very indicative)
	if strings.Contains(v, "-----BEGIN ") {
		return true
	}
	// Note: intentionally excludes "pk_" (Stripe publishable keys) and other
	// vendor prefixes that identify public/non-secret values by design.
	prefixes := []string{"sk_", "rk_", "akia", "asia", "aiza", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "npm_", "xoxb-", "xoxp-", "glpat-", "dop_v1_", "sq0atp-", "sq0csp-", "ya29.", "sg."}
	for _, p := range prefixes {
		if strings.HasPrefix(lv, p) {
			return true
		}
	}

	// Remove common separators before computing entropy
	comp := stripSeparators(v)
	if len(comp) < 12 {
		return false
	}

	ent := shannonEntropy(comp)
	// Tune threshold: 3.3–3.8 works well; higher = fewer false positives but misses some.
	return ent >= 3.4
}

func stripSeparators(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= 'A' && r <= 'Z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '+' || r == '/' || r == '=' || r == '_' || r == '-' || r == '.':
			b.WriteRune(r)
		}
	}
	return b.String()
}

func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, 64)
	for _, r := range s {
		freq[r]++
	}
	n := float64(len([]rune(s)))

	var ent float64
	for _, c := range freq {
		p := float64(c) / n
		ent -= p * (math.Log2(p))
	}
	return ent
}

func isMostlyOneChar(s string) bool {
	if len(s) < 8 {
		return false
	}
	count := make(map[rune]int, 8)
	for _, r := range s {
		count[r]++
	}
	max := 0
	total := 0
	for _, c := range count {
		total += c
		if c > max {
			max = c
		}
	}
	// if one rune accounts for >= 85% of the string, it's probably junk
	return float64(max)/float64(total) >= 0.85
}



func FindSecrets(content string) ([]*SecretMatch, map[string]struct{}) {
	var matches []*SecretMatch
	seen := make(map[string]struct{})

	patterns, err := LoadSecretPatterns()
	if err != nil {
		logify.Errorf("Error loading secret patterns: %v", err)
		return matches, seen
	}

	// Extract likely candidate windows (lines + string literals)
	candidates := extractSecretCandidateWindows(content)

	for _, pattern := range patterns {
		for _, chunk := range candidates {

			submatches := pattern.Re.FindAllStringSubmatch(chunk, -1)
			for _, sm := range submatches {

				raw := pickBestSecretGroup(sm)
				raw = strings.TrimSpace(raw)

				if !isPlausibleSecret(raw) {
					continue
				}

				if !passesEntropyHeuristic(raw) {
					continue
				}

				normalized := normalizeSecret(raw)
				if normalized == "" {
					continue
				}

				key := pattern.Name + "::" + normalized
				if _, ok := seen[key]; ok {
					continue
				}
				seen[key] = struct{}{}

				matches = append(matches, &SecretMatch{
					PatternName: pattern.Name,
					Value:       normalized,
				})
			}
		}
	}

	return matches, seen
}
