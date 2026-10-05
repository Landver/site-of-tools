package platform

import "unicode/utf8"

// Clip bounds a third-party string to at most limit bytes (limit ≥ 3). A cut
// lands on a rune boundary and ends in "…", so a reader can tell the value was
// shortened.
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
