package headless

import (
	"net/url"
	"regexp"
	"strings"
)

var inlineEndpointRE = regexp.MustCompile(`(?i)(?:["'` + "`" + `])((?:https?://|/)[a-z0-9_./?=&:%#@+~,-]{3,})(?:["'` + "`" + `])`)

func extractInlineEndpoints(pageURL, body string) []string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	matches := inlineEndpointRE.FindAllStringSubmatch(body, -1)
	seen := map[string]struct{}{}
	out := make([]string, 0, len(matches))
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		raw := strings.TrimSpace(m[1])
		if raw == "" {
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

func spaProbeScript() string {
	return `(() => {
		const out = new Set();
		const add = v => { if (v && typeof v === 'string') out.add(v); };
		document.querySelectorAll('[href]').forEach(e => add(e.getAttribute('href')));
		document.querySelectorAll('[src]').forEach(e => add(e.getAttribute('src')));
		document.querySelectorAll('form[action]').forEach(e => add(e.getAttribute('action')));
		performance.getEntriesByType('resource').forEach(e => add(e.name));
		return Array.from(out);
	})()`
}
