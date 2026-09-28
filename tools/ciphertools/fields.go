package ciphertools

import (
	"fmt"
	"strconv"
	"strings"
)

// intField reads a whole-number field: def when it is absent or blank, and an
// error naming the field and its range otherwise. The range is the cap, so it
// is checked here, before any work starts: for the Heavy ops the upper bound
// is what keeps one request from tying up the server.
func intField(in Input, name string, def, lo, hi int) (int, error) {
	v := strings.TrimSpace(in.Get(name))
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("%s: want a whole number, got %q", name, v)
	}
	switch {
	case n < lo:
		return 0, fmt.Errorf("%s: %d is below the minimum of %s", name, n, thousands(lo))
	case n > hi:
		return 0, fmt.Errorf("%s: %d is above the limit of %s", name, n, thousands(hi))
	}
	return n, nil
}

// thousands writes n with comma separators: 600000 as "600,000".
func thousands(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	s = strings.TrimPrefix(s, "-")
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		return "-" + s
	}
	return s
}
