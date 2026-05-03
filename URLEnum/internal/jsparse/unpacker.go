package jsparse

import (
	"regexp"
	"strconv"
	"strings"
)

type UnpackOptions struct {
	MaxPasses int
	MaxSize   int
}

func (o UnpackOptions) withDefaults() UnpackOptions {
	if o.MaxPasses <= 0 {
		o.MaxPasses = 4
	}
	if o.MaxSize <= 0 {
		o.MaxSize = 2 * 1024 * 1024
	}
	return o
}

type UnpackResult struct {
	Code    string
	Signals []string
}

var (
	evalStringRE = regexp.MustCompile(`(?is)eval\s*\(\s*(["'` + "`" + `])(.{1,200000}?)\1\s*\)`)
	atobCallRE   = regexp.MustCompile(`(?is)atob\s*\(\s*(["'` + "`" + `])([A-Za-z0-9+/=]{8,})\1\s*\)`)
	packerRE    = regexp.MustCompile(`(?is)eval\s*\(\s*function\s*\(p,a,c,k,e,(?:r|d)\).*?\.split\s*\(\s*['"]\|['"]\s*\)\s*\)\s*\)`)
)

func UnpackStatic(body string, opts UnpackOptions) UnpackResult {
	opts = opts.withDefaults()
	code := body
	signals := []string{}
	for pass := 0; pass < opts.MaxPasses; pass++ {
		before := code
		deob := DeobfuscateStatic(code)
		code = appendLimited(code, deob.Expanded, opts.MaxSize)
		signals = append(signals, deob.Signals...)
		code, signals = unpackEvalStrings(code, signals, opts.MaxSize)
		code, signals = unpackAtobCalls(code, signals, opts.MaxSize)
		code, signals = unpackPackerHints(code, signals, opts.MaxSize)
		if code == before || len(code) >= opts.MaxSize {
			break
		}
	}
	return UnpackResult{Code: code, Signals: uniqueStrings(signals)}
}

func DeepAnalyzeUnpacked(body string) []Finding {
	res := UnpackStatic(body, UnpackOptions{})
	return DeepAnalyze(res.Code)
}

func unpackEvalStrings(code string, signals []string, maxSize int) (string, []string) {
	for _, m := range evalStringRE.FindAllStringSubmatch(code, -1) {
		if len(m) < 3 {
			continue
		}
		payload := unquoteJS(m[1] + m[2] + m[1])
		if payload == "" || strings.Contains(payload, "function(p,a,c,k,e") {
			continue
		}
		code = appendLimited(code, payload, maxSize)
		signals = append(signals, "eval-string")
	}
	return code, signals
}

func unpackAtobCalls(code string, signals []string, maxSize int) (string, []string) {
	for _, m := range atobCallRE.FindAllStringSubmatch(code, -1) {
		if len(m) < 3 {
			continue
		}
		decoded := decodeBase64Maybe(m[2])
		if decoded == "" {
			continue
		}
		code = appendLimited(code, decoded, maxSize)
		signals = append(signals, "atob")
	}
	return code, signals
}

func unpackPackerHints(code string, signals []string, maxSize int) (string, []string) {
	if !packerRE.MatchString(code) {
		return code, signals
	}
	// Static packer support intentionally extracts the packed payload strings and dictionary hints
	// rather than executing the decoder. This avoids running arbitrary JavaScript while still
	// recovering many embedded endpoints from the p,a,c,k,e,d wrapper arguments.
	for _, s := range strRE.FindAllStringSubmatch(code, -1) {
		if len(s) != 2 {
			continue
		}
		v := strings.ReplaceAll(s[1], `\\`, `\`)
		if strings.Contains(v, "/") || strings.Contains(strings.ToLower(v), "api") || strings.Contains(strings.ToLower(v), "http") {
			code = appendLimited(code, v, maxSize)
		}
	}
	signals = append(signals, "packer-detected")
	return code, signals
}

func appendLimited(base, extra string, maxSize int) string {
	if extra == "" || extra == base {
		return base
	}
	if len(base)+len(extra)+1 > maxSize {
		remaining := maxSize - len(base) - 1
		if remaining <= 0 {
			return base
		}
		extra = extra[:remaining]
	}
	return base + "\n" + extra
}

func unquoteJS(raw string) string {
	s, err := strconv.Unquote(raw)
	if err == nil {
		return s
	}
	return strings.Trim(raw, "'\"`")
}
