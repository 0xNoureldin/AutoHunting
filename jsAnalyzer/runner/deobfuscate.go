package runner

import (
	"encoding/base64"
	"regexp"
	"strconv"
	"strings"
	"unicode"
)

type DeobfuscationResult struct {
	Expanded string
	Signals  []string
}

var (
	escapeSeqRE   = regexp.MustCompile(`(?:\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4})+`)
	atobRE        = regexp.MustCompile(`(?is)\batob\s*\(\s*["'` + "`" + `]([A-Za-z0-9+/=]{8,})["'` + "`" + `]\s*\)`)
	base64LitRE   = regexp.MustCompile(`["'` + "`" + `]([A-Za-z0-9+/]{20,}={0,2})["'` + "`" + `]`)
	concatRE      = regexp.MustCompile(`(?s)(["'` + "`" + `][^"'` + "`" + `]{1,300}["'` + "`" + `](?:\s*\+\s*["'` + "`" + `][^"'` + "`" + `]{1,300}["'` + "`" + `])+)`)
	arrayRE       = regexp.MustCompile(`(?is)\b(?:var|let|const)\s+[A-Za-z_$][\w$]*\s*=\s*\[((?:\s*["'` + "`" + `][^"'` + "`" + `]{1,300}["'` + "`" + `]\s*,?){2,})\]`)
	varAssignRE   = regexp.MustCompile(`(?is)\b(?:var|let|const)\s+([A-Za-z_$][\w$]*)\s*=\s*(["'` + "`" + `][^"'` + "`" + `]{1,300}["'` + "`" + `])`)
	fetchExprRE   = regexp.MustCompile(`(?is)\bfetch\s*\(\s*([^)]+)\)`)
	packerHintRE  = regexp.MustCompile(`(?is)eval\s*\(\s*function\s*\(p,a,c,k,e,(?:r|d)\).*?\.split\s*\(\s*['"]\|['"]\s*\)`)
	quotedValueRE = regexp.MustCompile(`["'` + "`" + `]([^"'` + "`" + `]{1,300})["'` + "`" + `]`)
)

func DeobfuscateStatic(body string, opts AnalyzeOptions) DeobfuscationResult {
	opts = defaultOptions(opts)
	maxSize := int(opts.MaxSize)
	if maxSize <= 0 {
		maxSize = 5 * 1024 * 1024
	}
	code := body
	signals := []string{}

	for pass := 0; pass < 4; pass++ {
		before := code
		code, signals = appendEscapedStrings(code, signals, maxSize)
		code, signals = appendBase64Strings(code, signals, maxSize)
		code, signals = appendConcats(code, signals, maxSize)
		code, signals = appendTemplatePrefixes(code, signals, maxSize)
		code, signals = appendArrayStrings(code, signals, maxSize)
		code, signals = appendVariableReconstructions(code, signals, maxSize)
		code, signals = appendEvalFunctionStrings(code, signals, maxSize)
		code, signals = appendPackerHints(code, signals, maxSize)
		if code == before || len(code) >= maxSize {
			break
		}
	}

	return DeobfuscationResult{Expanded: code, Signals: uniqueStrings(signals)}
}

func appendEscapedStrings(code string, signals []string, maxSize int) (string, []string) {
	for _, raw := range escapeSeqRE.FindAllString(code, -1) {
		decoded := decodeEscapes(raw)
		if usefulDecodedString(decoded) {
			code = appendLimited(code, decoded, maxSize)
			signals = append(signals, "escaped_string")
		}
	}
	return code, signals
}

func appendBase64Strings(code string, signals []string, maxSize int) (string, []string) {
	for _, re := range []*regexp.Regexp{atobRE, base64LitRE} {
		for _, m := range re.FindAllStringSubmatch(code, -1) {
			if len(m) < 2 {
				continue
			}
			decoded := decodeBase64Maybe(m[1])
			if usefulDecodedString(decoded) {
				code = appendLimited(code, decoded, maxSize)
				signals = append(signals, "base64_string")
			}
		}
	}
	return code, signals
}

func appendConcats(code string, signals []string, maxSize int) (string, []string) {
	for _, m := range concatRE.FindAllStringSubmatch(code, -1) {
		if len(m) < 2 {
			continue
		}
		parts := quotedValueRE.FindAllString(m[1], -1)
		var b strings.Builder
		for _, p := range parts {
			b.WriteString(unquoteJS(p))
		}
		joined := b.String()
		if usefulDecodedString(joined) {
			code = appendLimited(code, joined, maxSize)
			signals = append(signals, "string_concat")
		}
	}
	return code, signals
}

func appendTemplatePrefixes(code string, signals []string, maxSize int) (string, []string) {
	for _, lit := range scanStringLiterals(code, 3, 1000) {
		if lit.Quote != '`' || !strings.Contains(lit.Value, "${") {
			continue
		}
		if prefix := staticTemplatePrefix(lit.Value); prefix != "" {
			code = appendLimited(code, prefix, maxSize)
			signals = append(signals, "template_literal")
		}
	}
	return code, signals
}

func appendArrayStrings(code string, signals []string, maxSize int) (string, []string) {
	for _, arr := range arrayRE.FindAllStringSubmatch(code, -1) {
		if len(arr) < 2 {
			continue
		}
		for _, s := range quotedValueRE.FindAllStringSubmatch(arr[1], -1) {
			if len(s) == 2 && usefulDecodedString(s[1]) {
				code = appendLimited(code, s[1], maxSize)
			}
		}
		signals = append(signals, "string_array")
	}
	return code, signals
}

func appendVariableReconstructions(code string, signals []string, maxSize int) (string, []string) {
	vars := map[string]string{}
	for _, m := range varAssignRE.FindAllStringSubmatch(code, -1) {
		if len(m) == 3 {
			vars[m[1]] = unquoteJS(m[2])
		}
	}
	if len(vars) == 0 {
		return code, signals
	}
	for _, m := range fetchExprRE.FindAllStringSubmatch(code, -1) {
		if len(m) < 2 {
			continue
		}
		value, ok := evalStringExpression(m[1], vars)
		if ok && usefulDecodedString(value) {
			code = appendLimited(code, `fetch("`+value+`")`, maxSize)
			signals = append(signals, "variable_reconstruction")
		}
	}
	return code, signals
}

func appendEvalFunctionStrings(code string, signals []string, maxSize int) (string, []string) {
	for _, call := range []string{"eval", "Function"} {
		for _, payload := range extractStringCallArgs(code, call, maxEvalPayloadSize(maxSize)) {
			if payload != "" {
				code = appendLimited(code, payload, maxSize)
				signals = append(signals, "eval_string_extracted")
			}
		}
	}
	return code, signals
}

func appendPackerHints(code string, signals []string, maxSize int) (string, []string) {
	if !packerHintRE.MatchString(code) {
		return code, signals
	}
	if unpacked, ok := unpackDeanEdwards(code); ok && usefulDecodedString(unpacked) {
		code = appendLimited(code, unpacked, maxSize)
		signals = append(signals, "packer_unpacked")
	}
	for _, lit := range scanStringLiterals(code, 3, 1000) {
		value := strings.ReplaceAll(lit.Value, `\\`, `\`)
		if usefulDecodedString(value) {
			code = appendLimited(code, value, maxSize)
		}
	}
	return code, append(signals, "packer_detected")
}

func extractStringCallArgs(code, callName string, maxPayload int) []string {
	out := []string{}
	searchFrom := 0
	needle := callName
	for {
		idx := strings.Index(code[searchFrom:], needle)
		if idx < 0 {
			break
		}
		idx += searchFrom
		if !identifierBoundary(code, idx-1) || !identifierBoundary(code, idx+len(needle)) {
			searchFrom = idx + len(needle)
			continue
		}
		pos := idx + len(needle)
		for pos < len(code) && unicode.IsSpace(rune(code[pos])) {
			pos++
		}
		if pos >= len(code) || code[pos] != '(' {
			searchFrom = pos
			continue
		}
		pos++
		for pos < len(code) && unicode.IsSpace(rune(code[pos])) {
			pos++
		}
		if pos >= len(code) || (code[pos] != '"' && code[pos] != '\'' && code[pos] != '`') {
			searchFrom = pos
			continue
		}
		raw, end, ok := readQuotedAt(code, pos, maxPayload)
		if ok {
			out = append(out, unquoteJS(raw))
			searchFrom = end
			continue
		}
		searchFrom = pos + 1
	}
	return out
}

func identifierBoundary(s string, idx int) bool {
	if idx < 0 || idx >= len(s) {
		return true
	}
	r := rune(s[idx])
	return !(unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '$')
}

func readQuotedAt(s string, start int, maxPayload int) (string, int, bool) {
	if start < 0 || start >= len(s) {
		return "", start, false
	}
	quote := s[start]
	if quote != '"' && quote != '\'' && quote != '`' {
		return "", start, false
	}
	escaped := false
	for i := start + 1; i < len(s); i++ {
		if i-start > maxPayload {
			return "", i, false
		}
		c := s[i]
		if escaped {
			escaped = false
			continue
		}
		if c == '\\' {
			escaped = true
			continue
		}
		if c == quote {
			return s[start : i+1], i + 1, true
		}
	}
	return "", len(s), false
}

func maxEvalPayloadSize(maxSize int) int {
	limit := 256 * 1024
	if maxSize > 0 && maxSize < limit {
		return maxSize
	}
	return limit
}

func unpackDeanEdwards(code string) (string, bool) {
	args, ok := deanEdwardsArgs(code)
	if !ok || len(args) < 4 {
		return "", false
	}
	payload := unquoteJS(args[0])
	base, err := strconv.Atoi(strings.TrimSpace(args[1]))
	if err != nil || base < 2 || base > 62 {
		return "", false
	}
	count, err := strconv.Atoi(strings.TrimSpace(args[2]))
	if err != nil || count < 0 {
		return "", false
	}
	dictLiteral, ok := firstStringLiteral(args[3])
	if !ok {
		return "", false
	}
	dict := strings.Split(unquoteJS(dictLiteral), "|")
	if count > len(dict) {
		count = len(dict)
	}
	if payload == "" || len(payload) > 2*1024*1024 {
		return "", false
	}

	tokenRE := regexp.MustCompile(`\b[0-9A-Za-z]+\b`)
	unpacked := tokenRE.ReplaceAllStringFunc(payload, func(token string) string {
		idx, ok := decodePackerToken(token, base)
		if !ok || idx < 0 || idx >= count || idx >= len(dict) || dict[idx] == "" {
			return token
		}
		return dict[idx]
	})
	return unpacked, unpacked != payload
}

func deanEdwardsArgs(code string) ([]string, bool) {
	lower := strings.ToLower(code)
	start := strings.Index(lower, "eval(function(p,a,c,k,e,")
	if start < 0 {
		return nil, false
	}
	headerEnd := strings.Index(code[start:], "{")
	if headerEnd < 0 {
		return nil, false
	}
	openBrace := start + headerEnd
	closeBrace, ok := findMatchingDelimiter(code, openBrace, '{', '}')
	if !ok {
		return nil, false
	}
	pos := closeBrace + 1
	for pos < len(code) && unicode.IsSpace(rune(code[pos])) {
		pos++
	}
	if pos >= len(code) || code[pos] != '(' {
		return nil, false
	}
	closeParen, ok := findMatchingDelimiter(code, pos, '(', ')')
	if !ok {
		return nil, false
	}
	return splitTopLevelArgs(code[pos+1 : closeParen]), true
}

func findMatchingDelimiter(s string, open int, left, right byte) (int, bool) {
	if open < 0 || open >= len(s) || s[open] != left {
		return 0, false
	}
	depth := 0
	for i := open; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\'' || c == '`' {
			_, end, ok := readQuotedAt(s, i, maxEvalPayloadSize(len(s)))
			if !ok {
				return 0, false
			}
			i = end - 1
			continue
		}
		if c == left {
			depth++
		}
		if c == right {
			depth--
			if depth == 0 {
				return i, true
			}
		}
	}
	return 0, false
}

func splitTopLevelArgs(s string) []string {
	args := []string{}
	start := 0
	paren, bracket, brace := 0, 0, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' || c == '\'' || c == '`' {
			_, end, ok := readQuotedAt(s, i, maxEvalPayloadSize(len(s)))
			if !ok {
				break
			}
			i = end - 1
			continue
		}
		switch c {
		case '(':
			paren++
		case ')':
			if paren > 0 {
				paren--
			}
		case '[':
			bracket++
		case ']':
			if bracket > 0 {
				bracket--
			}
		case '{':
			brace++
		case '}':
			if brace > 0 {
				brace--
			}
		case ',':
			if paren == 0 && bracket == 0 && brace == 0 {
				args = append(args, strings.TrimSpace(s[start:i]))
				start = i + 1
			}
		}
	}
	args = append(args, strings.TrimSpace(s[start:]))
	return args
}

func firstStringLiteral(s string) (string, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] != '"' && s[i] != '\'' && s[i] != '`' {
			continue
		}
		raw, _, ok := readQuotedAt(s, i, maxEvalPayloadSize(len(s)))
		if ok {
			return raw, true
		}
	}
	return "", false
}

func decodePackerToken(token string, base int) (int, bool) {
	value := 0
	for _, r := range token {
		digit := -1
		switch {
		case r >= '0' && r <= '9':
			digit = int(r - '0')
		case r >= 'a' && r <= 'z':
			digit = int(r-'a') + 10
		case r >= 'A' && r <= 'Z':
			digit = int(r-'A') + 36
		}
		if digit < 0 || digit >= base {
			return 0, false
		}
		value = value*base + digit
	}
	return value, true
}

func evalStringExpression(expr string, vars map[string]string) (string, bool) {
	parts := strings.Split(expr, "+")
	var b strings.Builder
	used := false
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.HasPrefix(part, `"`) || strings.HasPrefix(part, `'`) || strings.HasPrefix(part, "`") {
			b.WriteString(unquoteJS(part))
			used = true
			continue
		}
		if v, ok := vars[part]; ok {
			b.WriteString(v)
			used = true
			continue
		}
		return "", false
	}
	return b.String(), used
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
	raw = strings.TrimSpace(raw)
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		return ""
	}
	if len(decoded) > 4096 {
		return ""
	}
	return string(decoded)
}

func usefulDecodedString(s string) bool {
	if len(s) < 3 || len(s) > 4096 {
		return false
	}
	l := strings.ToLower(s)
	return strings.Contains(s, "/") ||
		strings.Contains(l, "http") ||
		strings.Contains(l, "api") ||
		strings.Contains(l, "graphql") ||
		strings.Contains(l, "token") ||
		strings.Contains(l, "secret") ||
		strings.Contains(l, "akia") ||
		strings.Contains(l, "aiza") ||
		strings.Contains(l, "ghp_") ||
		strings.Contains(l, "xox")
}

func appendLimited(base, extra string, maxSize int) string {
	if extra == "" || hasExpandedLine(base, extra) {
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

func hasExpandedLine(base, extra string) bool {
	for _, line := range strings.Split(base, "\n") {
		if strings.TrimSpace(line) == strings.TrimSpace(extra) {
			return true
		}
	}
	return false
}

func unquoteJS(raw string) string {
	raw = strings.TrimSpace(raw)
	s, err := strconv.Unquote(raw)
	if err == nil {
		return s
	}
	return strings.Trim(raw, `"'`+"`")
}
