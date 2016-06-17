package fileServer

import (
	"path"
	"strings"
)

func hashedPath(p, h string) string {
	d, f := path.Split(p)

	h = makeHash(h)
	if h == "" {
		return p
	}
	i := strings.LastIndex(f, ".")
	if i > 0 {
		return d + f[:i] + "." + h + f[i:]
	}

	return d + f + "." + h
}

func canonicalPath(p string) string {
	d, f := path.Split(p)

	parts := strings.Split(f, ".")
	f = ""
	l := len(parts)
	index := 1
	if l > 2 && !(l == 3 && parts[0] == "") {
		index = 2
	}
	for i, part := range parts {
		if i == l-index && isHash(part) {
			continue
		}
		if i != 0 {
			f += "."
		}
		f += part
	}

	return d + f
}
