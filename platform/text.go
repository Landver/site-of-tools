package platform

import "unicode/utf8"

// Clip bounds s to limit bytes (limit ≥ 3), cut on a rune boundary and marked
// with "…" so a reader can tell it was shortened.
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
