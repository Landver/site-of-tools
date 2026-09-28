package tests

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"go/parser"
	gotoken "go/token"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func randomOf(t *testing.T, fields url.Values) *ciphertools.RandomResult {
	t.Helper()
	res, err := runOp(t, "random", fields, nil)
	if err != nil {
		t.Fatalf("random %v: %v", fields, err)
	}
	return res.(*ciphertools.RandomResult)
}

func unique(t *testing.T, vs []string) {
	t.Helper()
	seen := map[string]bool{}
	for _, v := range vs {
		if seen[v] {
			t.Fatalf("duplicate value %q in one batch", v)
		}
		seen[v] = true
	}
}

func TestRandomIsNotLiveOrHeavy(t *testing.T) {
	op, _ := ciphertools.Lookup("random")
	if op.Heavy {
		t.Error("random is Heavy")
	}
}

func TestRandomTokenFormats(t *testing.T) {
	cases := []struct {
		format string
		chars  int
		re     *regexp.Regexp
		decode func(string) ([]byte, error)
	}{
		{"hex", 64, regexp.MustCompile(`^[0-9a-f]+$`), hex.DecodeString},
		{"base64url", 43, regexp.MustCompile(`^[A-Za-z0-9_-]+$`), base64.RawURLEncoding.DecodeString},
		{"base64", 44, regexp.MustCompile(`^[A-Za-z0-9+/]+=$`), base64.StdEncoding.DecodeString},
		{"alnum", 43, regexp.MustCompile(`^[A-Za-z0-9]+$`), nil},
	}
	for _, c := range cases {
		r := randomOf(t, url.Values{"kind": {"token"}, "bytes": {"32"}, "format": {c.format}, "count": {"20"}})
		if len(r.Values) != 20 {
			t.Fatalf("%s: %d values", c.format, len(r.Values))
		}
		unique(t, r.Values)
		for _, v := range r.Values {
			if len(v) != c.chars || !c.re.MatchString(v) {
				t.Errorf("%s: %q", c.format, v)
			}
			if c.decode != nil {
				if b, err := c.decode(v); err != nil || len(b) != 32 {
					t.Errorf("%s: decodes to %d bytes (%v)", c.format, len(b), err)
				}
			}
		}
		// 8 bits a byte; letters and digits carry at least as much.
		if c.format == "alnum" {
			if want := 43 * math.Log2(62); math.Abs(r.EntropyBits-want) > 0.01 || r.EntropyBits < 256 {
				t.Errorf("alnum entropy %v", r.EntropyBits)
			}
		} else if r.EntropyBits != 256 {
			t.Errorf("%s entropy %v", c.format, r.EntropyBits)
		}
		if r.All != strings.Join(r.Values, "\n") {
			t.Error("copy-all text is not the values, one per line")
		}
	}
	// Defaults: one 32-byte hex token.
	r := randomOf(t, url.Values{})
	if r.Kind != "token" || len(r.Values) != 1 || len(r.Values[0]) != 64 {
		t.Errorf("defaults: %+v", r)
	}
	if r := randomOf(t, url.Values{"bytes": {"8"}}); !noted(r.Warnings, "128 bits") {
		t.Error("an 8-byte token is not flagged")
	}
}

func TestRandomBoundsEnforced(t *testing.T) {
	for _, f := range []url.Values{
		{"kind": {"token"}, "bytes": {"0"}},
		{"kind": {"token"}, "bytes": {"1025"}},
		{"kind": {"token"}, "count": {"21"}},
		{"kind": {"token"}, "format": {"base58"}},
		{"kind": {"password"}, "length": {"3"}},
		{"kind": {"password"}, "length": {"257"}},
		{"kind": {"password"}, "count": {"21"}},
		{"kind": {"password"}, "sets": {""}},
		{"kind": {"password"}, "sets": {"emoji"}},
		{"kind": {"uuid"}, "version": {"5"}},
		{"kind": {"uuid"}, "count": {"101"}},
		{"kind": {"ulid"}},
	} {
		if _, err := runOp(t, "random", f, nil); err == nil {
			t.Errorf("%v accepted", f)
		}
	}
}

func TestRandomPasswordCharsets(t *testing.T) {
	for sets, re := range map[string]*regexp.Regexp{
		"digits":            regexp.MustCompile(`^[0-9]{30}$`),
		"lower,upper":       regexp.MustCompile(`^[A-Za-z]{30}$`),
		"symbols":           regexp.MustCompile(`^[!-/:-@\[-` + "`" + `{-~]{30}$`),
		"lower,digits":      regexp.MustCompile(`^[a-z0-9]{30}$`),
		"upper digits":      regexp.MustCompile(`^[A-Z0-9]{30}$`),
		"lower,upper,lower": regexp.MustCompile(`^[A-Za-z]{30}$`),
	} {
		r := randomOf(t, url.Values{"kind": {"password"}, "length": {"30"}, "count": {"20"}, "sets": {sets}})
		for _, v := range r.Values {
			if !re.MatchString(v) {
				t.Errorf("sets=%s: %q", sets, v)
			}
		}
	}
	// A form sends each ticked box as its own value, plus the empty marker.
	r := randomOf(t, url.Values{"kind": {"password"}, "sets": {"", "digits", "upper"}, "length": {"12"}})
	if !regexp.MustCompile(`^[A-Z0-9]{12}$`).MatchString(r.Values[0]) {
		t.Errorf("repeated sets field: %q", r.Values[0])
	}
	// Absent means all four, 94 characters.
	r = randomOf(t, url.Values{"kind": {"password"}})
	if len(r.Values[0]) != 20 || len(r.Alphabet) != 94 {
		t.Errorf("defaults: %q from %d characters", r.Values[0], len(r.Alphabet))
	}
}

func TestRandomPasswordExcludesAmbiguous(t *testing.T) {
	for range 20 {
		r := randomOf(t, url.Values{"kind": {"password"}, "length": {"256"}, "count": {"20"}, "exclude_ambiguous": {"on"}})
		for _, v := range r.Values {
			if strings.ContainsAny(v, "0O1lI|`") {
				t.Fatalf("ambiguous character in %q", v)
			}
		}
		if strings.ContainsAny(r.Alphabet, "0O1lI|`") || len(r.Alphabet) != 94-7 {
			t.Fatalf("alphabet %q", r.Alphabet)
		}
	}
	// The full alphabet is untouched afterwards (the sets are copied, not trimmed in place).
	if r := randomOf(t, url.Values{"kind": {"password"}}); len(r.Alphabet) != 94 {
		t.Fatalf("alphabet shrank to %d after an exclude run", len(r.Alphabet))
	}
}

// Length 4 with all four sets is the hardest case for "one of each".
func TestRandomPasswordHasOneOfEachSet(t *testing.T) {
	sets := []string{"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789", "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~"}
	for range 50 {
		r := randomOf(t, url.Values{"kind": {"password"}, "length": {"4"}, "count": {"20"}})
		for _, v := range r.Values {
			for _, s := range sets {
				if !strings.ContainsAny(v, s) {
					t.Fatalf("%q has nothing from %q", v, s)
				}
			}
		}
	}
}

func TestRandomPasswordEntropy(t *testing.T) {
	// One set: exactly length × log2(size).
	r := randomOf(t, url.Values{"kind": {"password"}, "length": {"10"}, "sets": {"digits"}})
	if want := 10 * math.Log2(10); math.Abs(r.EntropyBits-want) > 0.01 {
		t.Errorf("digits: %v bits, want %v", r.EntropyBits, want)
	}
	if !noted(r.Warnings, "bits") {
		t.Error("a 33-bit password is not flagged")
	}
	// All four sets: the one-of-each rule costs a little under length × log2(94).
	r = randomOf(t, url.Values{"kind": {"password"}, "length": {"20"}})
	full := 20 * math.Log2(94)
	if r.EntropyBits >= full || r.EntropyBits < full-1 {
		t.Errorf("all sets: %v bits, want just under %v", r.EntropyBits, full)
	}
	if r.Entropy == "" || !strings.HasSuffix(r.Entropy, " bits") {
		t.Errorf("entropy text %q", r.Entropy)
	}
}

// Rejection sampling, not modulo: with b % 10 over bytes, digits 0-5 would
// come up 26/256 of the time and 6-9 25/256. Over ~5M digits that is 12
// standard deviations; the bound here is 6.
func TestRandomPasswordIsUniform(t *testing.T) {
	if testing.Short() {
		t.Skip("statistical")
	}
	var counts [10]int
	total := 0
	for range 1000 {
		r := randomOf(t, url.Values{"kind": {"password"}, "length": {"256"}, "count": {"20"}, "sets": {"digits"}})
		for _, v := range r.Values {
			for i := 0; i < len(v); i++ {
				counts[v[i]-'0']++
				total++
			}
		}
	}
	sigma := math.Sqrt(0.1 * 0.9 / float64(total))
	for d, n := range counts {
		if f := float64(n) / float64(total); math.Abs(f-0.1) > 6*sigma {
			t.Errorf("digit %d: frequency %.5f, want 0.1 ± %.5f", d, f, 6*sigma)
		}
	}
}

var uuidRE = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-([0-9a-f])[0-9a-f]{3}-([0-9a-f])[0-9a-f]{3}-[0-9a-f]{12}$`)

func TestRandomUUIDVersionAndVariant(t *testing.T) {
	for _, version := range []string{"4", "7"} {
		r := randomOf(t, url.Values{"kind": {"uuid"}, "version": {version}, "count": {"100"}})
		if len(r.Values) != 100 {
			t.Fatalf("v%s: %d values", version, len(r.Values))
		}
		unique(t, r.Values)
		for _, v := range r.Values {
			m := uuidRE.FindStringSubmatch(v)
			if m == nil || m[1] != version || !strings.Contains("89ab", m[2]) {
				t.Fatalf("v%s: %q", version, v)
			}
		}
	}
	if r := randomOf(t, url.Values{"kind": {"uuid"}}); r.EntropyBits != 122 || noted(r.Warnings, "creation time") {
		t.Errorf("v4 default: %v bits, %+v", r.EntropyBits, r.Warnings)
	}
}

func TestRandomUUIDv7EmbedsNow(t *testing.T) {
	before := time.Now().UnixMilli()
	r := randomOf(t, url.Values{"kind": {"uuid"}, "version": {"7"}, "count": {"50"}})
	after := time.Now().UnixMilli()
	for _, v := range r.Values {
		ms, err := strconv.ParseInt(strings.ReplaceAll(v, "-", "")[:12], 16, 64)
		if err != nil || ms < before || ms > after {
			t.Fatalf("%s: timestamp %d not within [%d, %d]", v, ms, before, after)
		}
	}
	if !slices.IsSorted(r.Values) {
		t.Error("a v7 batch is not in order")
	}
	if !noted(r.Warnings, "creation time") || r.Created == "" || !noted(r.Warnings, r.Created) {
		t.Errorf("v7 warning: %q %+v", r.Created, r.Warnings)
	}
	if r.EntropyBits != 74 {
		t.Errorf("v7 entropy %v", r.EntropyBits)
	}
}

// "Randomness is crypto/rand only": math/rand may not be imported by any file
// that runs in production, here or in the wasm engine.
func TestNoMathRandImports(t *testing.T) {
	root := ".." // go test runs in tools/ciphertools/tests
	n := 0
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(gotoken.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		n++
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p == "math/rand" || p == "math/rand/v2" {
				t.Errorf("%s imports %s", path, p)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 {
		t.Fatalf("only %d Go files found under %s; is the walk rooted right?", n, root)
	}
}

func TestRenderRandomFragment(t *testing.T) {
	html := render(t, "random", url.Values{"kind": {"uuid"}, "count": {"3"}})
	if strings.Count(html, `data-copy="`) != 4 || !strings.Contains(html, "Copy all") {
		t.Errorf("want three copy buttons and a copy-all: %s", html)
	}
	if html := render(t, "random", url.Values{}); strings.Contains(html, "Copy all") {
		t.Error("copy-all shown for a single value")
	}
}

func TestRandomAPIAndNoJSRouting(t *testing.T) {
	e := newCipherApp(t)
	rec := do(t, e, http.MethodPost, "/random", `{"kind":"password","length":16,"sets":"digits"}`, "application/json", asAPI)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("code %d, Cache-Control %q: %s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body)
	}
	var got struct{ Values []string }
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got.Values) != 1 ||
		!regexp.MustCompile(`^[0-9]{16}$`).MatchString(got.Values[0]) {
		t.Fatalf("got %+v (%v)", got, err)
	}

	// No JS: the result lands in the box of the form that was sent.
	html := do(t, e, http.MethodPost, "/random", "kind=uuid&version=4", form, asBrowser).Body.String()
	box := func(id string) string {
		s := html[strings.Index(html, `id="`+id+`"`):]
		return s[:strings.Index(s, "</section>")]
	}
	if !uuidRE.MatchString(regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f-]{27}`).FindString(box("random-uuid-result"))) {
		t.Error("UUID not in the UUID box")
	}
	if strings.Contains(box("random-token-result"), "Entropy") || strings.Contains(box("random-password-result"), "Entropy") {
		t.Error("UUID result rendered in another box too")
	}
	if !strings.Contains(html, "tab: 'uuid'") {
		t.Error("the UUID tab is not the one open")
	}
}
