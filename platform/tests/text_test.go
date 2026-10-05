package tests

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/Landver/site-of-tools/platform"
)

func TestClip(t *testing.T) {
	for _, c := range []struct {
		in    string
		limit int
		want  string
	}{
		{"abcdef", 6, "abcdef"},
		{"abcdefg", 6, "abc…"},
		{"aééb", 5, "a…"},
		{"ééé", 5, "é…"},
	} {
		if got := platform.Clip(c.in, c.limit); got != c.want {
			t.Errorf("Clip(%q, %d) = %q, want %q", c.in, c.limit, got, c.want)
		}
	}

	hostile := strings.Repeat("ab‮é", 100_000)
	for _, limit := range []int{3, 4, 100, 256, 300, 2048} {
		got := platform.Clip(hostile, limit)
		if len(got) > limit || !utf8.ValidString(got) || !strings.HasSuffix(got, "…") {
			t.Errorf("Clip(hostile, %d) = %d bytes, valid UTF-8 %v, marked %v", limit, len(got), utf8.ValidString(got), strings.HasSuffix(got, "…"))
		}
	}
}
