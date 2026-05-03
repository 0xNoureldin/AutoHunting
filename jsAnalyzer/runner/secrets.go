package runner

import (
	"math"
	"regexp"
	"sort"
	"strings"
)

type secretRule struct {
	Type       string
	Re         *regexp.Regexp
	Confidence string
}

var highConfidenceSecretRules = []secretRule{
	{"aws_access_key_id", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`), "high"},
	{"google_api_key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`), "high"},
	{"github_token", regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}\b`), "high"},
	{"github_token", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,255}\b`), "high"},
	{"gitlab_token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,255}\b`), "high"},
	{"slack_token", regexp.MustCompile(`\bxox[bpar]-[A-Za-z0-9-]{20,255}\b`), "high"},
	{"stripe_key", regexp.MustCompile(`\b(?:sk_live|rk_live|pk_live)_[A-Za-z0-9]{16,255}\b`), "high"},
	{"sendgrid_key", regexp.MustCompile(`\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b`), "high"},
	{"jwt", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\b`), "high"},
	{"sentry_dsn", regexp.MustCompile(`https://[A-Za-z0-9]+@(?:[a-z0-9.-]+\.)?sentry\.io/[0-9]+`), "high"},
	{"private_key", regexp.MustCompile(`(?s)-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |OPENSSH )?PRIVATE KEY-----`), "high"},
	{"aws_secret_key", regexp.MustCompile(`(?i)\baws.{0,30}(?:secret|access).{0,30}["'` + "`" + `]([0-9A-Za-z/+]{40})["'` + "`" + `]`), "high"},
	{"legacy_slack_token", regexp.MustCompile(`xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}`), "high"},
}

var assignmentSecretRE = regexp.MustCompile(`(?is)\b(api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|secret|client[_-]?secret|auth[_-]?token|bearer|password|passwd|pwd)\b\s*[:=]\s*["'` + "`" + `]([^"'` + "`" + `]{8,500})["'` + "`" + `]`)

func LoadSecretPatterns() ([]SecretPattern, error) {
	patterns := []SecretPattern{
		{Name: "AWS Access Key", Re: regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
		{Name: "AWS Secret Key", Re: regexp.MustCompile(`(?i)aws(.{0,20})?(secret)?(.{0,20})?['"][0-9a-zA-Z/+]{40}['"]`)},
		{Name: "Google API Key", Re: regexp.MustCompile(`AIza[0-9A-Za-z-_]{35}`)},
		{Name: "Slack Token", Re: regexp.MustCompile(`xox[baprs]-[0-9]{10,}-[0-9]{10,}-[a-zA-Z0-9]{24,}`)},
		{Name: "GitHub Token", Re: regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,255}`)},
		{Name: "GitLab Token", Re: regexp.MustCompile(`glpat-[A-Za-z0-9_-]{20,255}`)},
		{Name: "Stripe Live Key", Re: regexp.MustCompile(`(?:sk_live|rk_live|pk_live)_[A-Za-z0-9]{16,255}`)},
		{Name: "SendGrid API Key", Re: regexp.MustCompile(`SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}`)},
		{Name: "JWT", Re: regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}`)},
		{Name: "Private Key", Re: regexp.MustCompile(`(?s)-----BEGIN (?:RSA |OPENSSH )?PRIVATE KEY-----.*?-----END (?:RSA |OPENSSH )?PRIVATE KEY-----`)},
	}
	return patterns, nil
}

func ExtractSecrets(body string) []SecretFinding {
	candidates := extractSecretCandidateWindows(body)
	findings := make([]SecretFinding, 0)
	add := func(secretType, value, confidence, context string) {
		value = normalizeSecret(value)
		if !isPlausibleSecret(value) || !passesEntropyHeuristic(value) {
			return
		}
		findings = append(findings, SecretFinding{
			Type:       secretType,
			Value:      value,
			Masked:     MaskSecret(value),
			Confidence: confidence,
			Context:    context,
		})
	}

	for _, chunk := range candidates {
		for _, rule := range highConfidenceSecretRules {
			for _, sm := range rule.Re.FindAllStringSubmatch(chunk, -1) {
				add(rule.Type, pickBestSecretGroup(sm), rule.Confidence, contextForValue(chunk, pickBestSecretGroup(sm)))
			}
		}
		for _, sm := range assignmentSecretRE.FindAllStringSubmatch(chunk, -1) {
			if len(sm) < 3 {
				continue
			}
			add("assignment_"+strings.ToLower(strings.ReplaceAll(sm[1], "-", "_")), sm[2], "medium", "assignment: "+sm[1])
		}
	}

	return dedupeSecretFindings(findings)
}

func FindSecrets(content string) ([]*SecretMatch, map[string]struct{}) {
	findings := ExtractSecrets(content)
	seen := make(map[string]struct{}, len(findings))
	matches := make([]*SecretMatch, 0, len(findings))
	for _, finding := range findings {
		key := finding.Type + "::" + finding.Masked
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		matches = append(matches, &SecretMatch{PatternName: finding.Type, Value: finding.Masked})
	}
	return matches, seen
}

func MaskSecret(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	prefixes := []string{"github_pat_", "sk_live_", "rk_live_", "pk_live_", "glpat-", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "AKIA", "ASIA", "AIza", "SG."}
	for _, prefix := range prefixes {
		if strings.HasPrefix(value, prefix) {
			if len(value) <= len(prefix)+4 {
				return prefix + "********"
			}
			return prefix + "********" + value[len(value)-4:]
		}
	}
	if len(value) <= 8 {
		return "********"
	}
	return value[:4] + "********" + value[len(value)-4:]
}

func redactSecretFinding(f SecretFinding) SecretFinding {
	if f.Masked == "" {
		f.Masked = MaskSecret(f.Value)
	}
	if f.Context != "" {
		f.Context = redactSecretContext(f.Context, f.Value, f.Masked)
	}
	return f
}

func redactSecretContext(context, value, masked string) string {
	if context == "" {
		return ""
	}
	if value != "" && masked != "" {
		context = strings.ReplaceAll(context, value, masked)
	}
	for _, rule := range highConfidenceSecretRules {
		context = rule.Re.ReplaceAllStringFunc(context, func(match string) string {
			return MaskSecret(normalizeSecret(match))
		})
	}
	return context
}

func extractSecretCandidateWindows(s string) []string {
	const maxWin = 4000
	var out []string
	lines := strings.Split(s, "\n")
	for _, line := range lines {
		l := strings.TrimSpace(line)
		ll := strings.ToLower(l)
		if l == "" {
			continue
		}
		for _, token := range []string{"key", "token", "secret", "pass", "auth", "bearer", "api", "x-", "akia", "asia", "-----begin", "sk_", "aiza", "ghp_", "github_pat_", "glpat-", "sg.", "xoxb-", "xoxp-", "firebase"} {
			if strings.Contains(ll, token) {
				if len(l) > maxWin {
					l = l[:maxWin]
				}
				out = append(out, l)
				break
			}
		}
	}
	for _, lit := range scanStringLiterals(s, 6, 800) {
		out = append(out, lit.Value)
	}
	if len(out) == 0 {
		if len(s) > 200000 {
			out = append(out, s[:200000])
		} else {
			out = append(out, s)
		}
	}
	return out
}

func pickBestSecretGroup(submatch []string) string {
	if len(submatch) == 0 {
		return ""
	}
	for i := len(submatch) - 1; i >= 1; i-- {
		if strings.TrimSpace(submatch[i]) != "" {
			return submatch[i]
		}
	}
	return submatch[0]
}

func isPlausibleSecret(v string) bool {
	if v == "" || len(v) < 8 || len(v) > 1000 {
		return false
	}
	lv := strings.ToLower(v)
	bad := []string{"changeme", "change-me", "your_api_key", "your-api-key", "api_key_here", "example", "sample", "dummy", "test", "placeholder", "xxxx", "1111", "0000", "null", "undefined", "true", "false", "localhost", "127.0.0.1"}
	for _, b := range bad {
		if strings.Contains(lv, b) {
			return false
		}
	}
	if strings.HasPrefix(lv, "http://") || strings.HasPrefix(lv, "https://") {
		return strings.Contains(lv, "sentry.io/")
	}
	return !isMostlyOneChar(v)
}

func normalizeSecret(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '"' && v[len(v)-1] == '"') || (v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '`' && v[len(v)-1] == '`') {
			v = strings.TrimSpace(v[1 : len(v)-1])
		}
	}
	v = strings.TrimRight(v, `,;:)]}>"'`)
	if len(v) > 300 {
		v = v[:300] + "...(truncated)"
	}
	return v
}

func passesEntropyHeuristic(v string) bool {
	lv := strings.ToLower(v)
	if strings.Contains(v, "-----BEGIN ") || strings.Contains(lv, "sentry.io/") {
		return true
	}
	for _, p := range []string{"sk_live_", "rk_live_", "pk_live_", "akia", "asia", "aiza", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_", "glpat-", "sg.", "xoxb-", "xoxp-", "xoxa-", "xoxr-", "eyj"} {
		if strings.HasPrefix(lv, p) {
			return true
		}
	}
	comp := stripSeparators(v)
	if len(comp) < 12 {
		return false
	}
	return shannonEntropy(comp) >= 3.2
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
		ent -= p * math.Log2(p)
	}
	return ent
}

func isMostlyOneChar(s string) bool {
	if len(s) < 8 {
		return false
	}
	count := map[rune]int{}
	total := 0
	maxCount := 0
	for _, r := range s {
		count[r]++
		total++
		if count[r] > maxCount {
			maxCount = count[r]
		}
	}
	return float64(maxCount)/float64(total) >= 0.85
}

func contextForValue(chunk, value string) string {
	idx := strings.Index(chunk, value)
	if idx < 0 {
		return strings.TrimSpace(chunk)
	}
	return contextSnippet(chunk, idx, idx+len(value))
}

func dedupeSecretFindings(in []SecretFinding) []SecretFinding {
	seen := map[string]SecretFinding{}
	for _, f := range in {
		if f.Masked == "" {
			f.Masked = MaskSecret(f.Value)
		}
		if f.Masked == "" {
			continue
		}
		key := f.Type + "\x00" + f.Source + "\x00" + f.Masked
		if _, ok := seen[key]; !ok {
			seen[key] = f
		}
	}
	out := make([]SecretFinding, 0, len(seen))
	for _, f := range seen {
		out = append(out, f)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type == out[j].Type {
			return out[i].Masked < out[j].Masked
		}
		return out[i].Type < out[j].Type
	})
	return out
}

func limitSecretFindings(in []SecretFinding, max int) []SecretFinding {
	if max <= 0 || len(in) <= max {
		return in
	}
	return in[:max]
}
