package jsparse

import "regexp"

var endpointRE = regexp.MustCompile(`(?i)(?:["'` + "`" + `])((?:https?://|/)[a-z0-9_./?=&:%#@+~,-]{3,})(?:["'` + "`" + `])`)

func ExtractEndpoints(body string) []string {
	matches := endpointRE.FindAllStringSubmatch(body, -1)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		v := m[1]
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}

	return out
}
