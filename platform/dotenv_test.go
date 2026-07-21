package platform

// White-box test (pkg platform): parseDotEnv + mergeEnv are unexported dev
// helpers → sits beside code per ARCHITECTURE §9, not black-box tests/ pkg.

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
		"LISTEN_ADDR": ":9090", // whitespace around key+value trimmed
		"BASE_DOMAIN": "corpberry.com",
		"TOKEN":       "a=b=c", // only first "=" splits → value can contain "="
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
	// Blank lines, comments (incl. indented), line w/o "=" → all skipped.
	if _, ok := got["NOT_A_PAIR"]; ok {
		t.Errorf("a line without '=' must be skipped, got %q", got["NOT_A_PAIR"])
	}
}

func TestMergeEnvNeverOverrides(t *testing.T) {
	// Var already in real env must win over .env value.
	t.Setenv("PLATFORM_DOTENV_EXISTING", "from-shell")
	// Var not yet set → filled from pairs; clean up after.
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
