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
	u.Path = p

	switch mode {
	case Exact:
		return u.String()

	case ParamAware:
		q := u.Query()
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, strings.ToLower(k))
		}
		sort.Strings(keys)
		u.RawQuery = strings.Join(keys, "&")
		return u.Scheme + "://" + u.Host + u.Path + "?" + u.RawQuery

	case PathOnly:
		u.RawQuery = ""
		return u.Scheme + "://" + u.Host + u.Path

	default:
		return u.String()
	}
}
