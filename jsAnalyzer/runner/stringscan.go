package runner

import "strings"

type stringLiteral struct {
	Raw   string
	Value string
	Start int
	End   int
	Quote byte
}

func scanStringLiterals(s string, minLen, maxLen int) []stringLiteral {
	var out []stringLiteral
	for i := 0; i < len(s); i++ {
		q := s[i]
		if q != '"' && q != '\'' && q != '`' {
			continue
		}
		start := i
		i++
		escaped := false
		var b strings.Builder
		for i < len(s) {
			c := s[i]
			if escaped {
				b.WriteByte('\\')
				b.WriteByte(c)
				escaped = false
				i++
				continue
			}
			if c == '\\' {
				escaped = true
				i++
				continue
			}
			if c == q {
				raw := s[start : i+1]
				value := b.String()
				if len(value) >= minLen && (maxLen <= 0 || len(value) <= maxLen) {
					out = append(out, stringLiteral{Raw: raw, Value: value, Start: start, End: i + 1, Quote: q})
				}
				break
			}
			if q != '`' && (c == '\n' || c == '\r') {
				break
			}
			b.WriteByte(c)
			i++
		}
	}
	return out
}
