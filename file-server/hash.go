package fileServer

import "encoding/base32"

const hashCheckChars = "0123456789abcdefghjkmnpqrstvwxyz"

var base32Encoding = base32.NewEncoding(hashCheckChars)

func isHash(h string) bool {
	if len(h) != 8 {
		return false
	}
	c := h[7]
	h = h[:7]
	m := 0
	for _, r := range h {
		m += int(r) % 32
	}
	m = m % 32
	if c == hashCheckChars[m] {
		return true
	}
	return false
}

func makeHash(h string) string {
	if len(h) < 7 {
		return ""
	}
	h = h[:7]
	m := 0
	for _, r := range h {
		m += int(r) % 32
	}
	m = m % 32
	return h + string(hashCheckChars[m])
}
