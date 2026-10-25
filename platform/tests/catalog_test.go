package tests

import (
	"testing"

	"github.com/Landver/site-of-tools/platform"
)

func TestSectionBadgeCountsItsTools(t *testing.T) {
	for n, want := range map[int]string{1: "1 tool", 4: "4 tools"} {
		if got := (platform.ToolSection{Tools: make([]platform.ToolItem, n)}).Badge(); got != want {
			t.Errorf("%d tools: Badge() = %q, want %q", n, got, want)
		}
	}
}
