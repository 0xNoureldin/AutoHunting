package jsparse

import (
	"encoding/base64"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

type DeobfuscationResult struct {
	Expanded string
	Signals  []string
}

var (
	escapeRE = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})+`)
	b64RE    = regexp.MustCompile(`["'` + "`" + `]([A-Za-z0-9+/]{20,}={0,2})["'` + "`" + `]`)
	concatRE = regexp.MustCompile(`["'` + "`" + `]([^"'` + "`" + `]{1,120})["'` + "`" + `]\s*\+\s*["'` + "`" + `]([^"'` + "`" + `]{1,120})["'` + "`" + `]`)
	arrayRE  = regexp.MustCompile(`(?s)(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*\[((?:\s*["'` + "`" + `][^"'` + "`" + `]{1,300}["'` + "`" + `]\s*,?){2,})\]`)
	strRE    = regexp.MustCompile(`["'` + "`" + `]([^"'` + "`" + `]{1,300})["'` + "`" + `]`)
)

func DeobfuscateStatic(body string) DeobfuscationResult {
	out := body
	signals := []string{}
	for _, raw := range escapeRE.FindAllString(body, -1) {
		decoded := decodeEscapes(raw)
		if decoded != "" && decoded != raw {
			out += "\n" + decoded
			signals = append(signals, "escaped-string")
		}
	}
	for _, m := range b64RE.FindAllStringSubmatch(body, -1) {
		if len(m) < 2 {
			continue
		}
		decoded := decodeBase64Maybe(m[1])
		if decoded != "" {
			out += "\n" + decoded
			signals = append(signals, "base64-string")
		}
	}
	for _, m := range concatRE.FindAllStringSubmatch(body, -1) {
		if len(m) == 3 {
			out += "\n" + m[1] + m[2]
			signals = append(signals, "string-concat")
		}
	}
	for _, arr := range arrayRE.FindAllStringSubmatch(body, -1) {
		if len(arr) < 3 {
			continue
		}
		for _, s := range strRE.FindAllStringSubmatch(arr[2], -1) {
			if len(s) == 2 {
				out += "\n" + s[1]
			}
		}
		signals = append(signals, "string-array")
	}
	return DeobfuscationResult{Expanded: out, Signals: uniqueStrings(signals)}
}

func DeepAnalyzeDeobfuscated(body string) []Finding {
	deob := DeobfuscateStatic(body)
	return DeepAnalyze(deob.Expanded)
}

func decodeEscapes(raw string) string {
	converted := strings.ReplaceAll(raw, `\x`, `\u00`)
	s, err := strconv.Unquote(`"` + converted + `"`)
	if err != nil {
		return ""
	}
	return s
}

func decodeBase64Maybe(raw string) string {
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	s := string(decoded)
	if len(s) > 4096 {
		return ""
	}
	if strings.Contains(s, "/") || strings.Contains(s, "http") || strings.Contains(s, "api") || strings.Contains(s, "graphql") {
		if _, err := url.Parse(s); err == nil || strings.Contains(s, "/") {
			return s
		}
	}
	return ""
}

func uniqueStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
