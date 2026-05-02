package normalize

import (
	"net/url"
	"path"
	"sort"
	"strings"
)

type Mode int

const (
	Exact Mode = iota
	ParamAware
	PathOnly
)

func Key(raw string, mode Mode) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""

	p := path.Clean(u.EscapedPath())
	if p == "." || p == "" {
		p = "/"
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	base := u.Scheme + "://" + u.Host + p

	switch mode {
	case Exact:
		if u.RawQuery == "" {
			return base
		}
		return base + "?" + u.RawQuery

	case ParamAware:
		q := u.Query()
		seen := map[string]struct{}{}
		for k := range q {
			seen[strings.ToLower(k)] = struct{}{}
		}
		keys := make([]string, 0, len(seen))
		for k := range seen {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		if len(keys) == 0 {
			return base
		}
		return base + "?" + strings.Join(keys, "&")

	case PathOnly:
		return base

	default:
		if u.RawQuery == "" {
			return base
		}
		return base + "?" + u.RawQuery
	}
}
