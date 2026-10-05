package platform

import "unicode/utf8"

// Clip cuts s to at most limit bytes (limit ≥ 3) on a rune boundary, marking the cut with "…".
func Clip(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	const mark = "…"
	n := max(limit-len(mark), 0)
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + mark
}
