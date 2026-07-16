package platform

// White-box test (package platform): parseDotEnv and mergeEnv are unexported dev
// helpers, so this sits beside the code per ARCHITECTURE §9 rather than in the
// black-box tests/ package.

import (
	"os"
	"strings"
	"testing"
)

func TestParseDotEnv(t *testing.T) {
	const in = `
# a comment
APP_ENV=prod
LISTEN_ADDR = :9090

  # indented comment
BASE_DOMAIN=corpberry.com
NOT_A_PAIR
TOKEN=a=b=c
PADDED =  spaced value
`
	got := parseDotEnv(strings.NewReader(in))
	want := map[string]string{
		"APP_ENV":     "prod",
		"LISTEN_ADDR": ":9090", // whitespace around key and value trimmed
		"BASE_DOMAIN": "corpberry.com",
		"TOKEN":       "a=b=c", // only the first "=" splits; value may contain "="
		"PADDED":      "spaced value",
	}
	if len(got) != len(want) {
		t.Fatalf("parsed %d pairs, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	// Blank lines, comments (incl. indented), and a line without "=" are all skipped.
	if _, ok := got["NOT_A_PAIR"]; ok {
		t.Errorf("a line without '=' must be skipped, got %q", got["NOT_A_PAIR"])
	}
}

func TestMergeEnvNeverOverrides(t *testing.T) {
	// A var already in the real environment must win over the .env value.
	t.Setenv("PLATFORM_DOTENV_EXISTING", "from-shell")
	// A var not yet set should be filled from the pairs; clean it up after.
	const freshKey = "PLATFORM_DOTENV_FRESH"
	os.Unsetenv(freshKey)
	t.Cleanup(func() { os.Unsetenv(freshKey) })

	mergeEnv(map[string]string{
		"PLATFORM_DOTENV_EXISTING": "from-dotenv",
		freshKey:                   "from-dotenv",
	})

	if got := os.Getenv("PLATFORM_DOTENV_EXISTING"); got != "from-shell" {
		t.Errorf("existing var overridden: got %q, want %q (real env must win)", got, "from-shell")
	}
	if got := os.Getenv(freshKey); got != "from-dotenv" {
		t.Errorf("unset var not filled: got %q, want %q", got, "from-dotenv")
	}
}
