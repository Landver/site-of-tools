package tests

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// TestFieldSpecsMatchTheCode: every field an op file's code reads is declared
// by an op it registers, and every declared field is read. MCP generates the
// tool schemas from Fields, so drift either way is an argument the tool lies about.
func TestFieldSpecsMatchTheCode(t *testing.T) {
	registers := regexp.MustCompile(`register\(Op\{Name: "([^"]+)"`)
	fieldVar := regexp.MustCompile(`(\w+) += Field\{Name: "([^"]+)"`)
	reads := regexp.MustCompile(`in\.(?:Get\("([^"]+)"\)|Fields\["([^"]+)"\]|Files\["([^"]+)"\]|(now)\(\))|intField\(in, (\w+)`)
	paths, _ := filepath.Glob("../*.go") // go test runs in tools/ciphertools/tests
	srcs, vars := map[string]string{}, map[string]string{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		srcs[p] = string(b)
		for _, m := range fieldVar.FindAllStringSubmatch(string(b), -1) {
			vars[m[1]] = m[2]
		}
	}
	ops := map[string]ciphertools.Op{}
	for _, op := range ciphertools.Ops() {
		ops[op.Name] = op
	}
	seen := 0
	for p, src := range srcs {
		declared, read := map[string]bool{}, map[string]bool{}
		for _, m := range registers.FindAllStringSubmatch(src, -1) {
			seen++
			for _, f := range ops[m[1]].Fields {
				declared[f.Name] = true
			}
		}
		if len(declared) == 0 {
			continue
		}
		for _, m := range reads.FindAllStringSubmatch(src, -1) {
			name := m[1] + m[2] + m[3] + m[4] + vars[m[5]]
			read[name] = true
			if !declared[name] {
				t.Errorf("%s reads %q, which no op it registers declares", p, name)
			}
		}
		for name := range declared {
			if !read[name] {
				t.Errorf("%s declares %q, which its code never reads", p, name)
			}
		}
	}
	if seen != len(ops) {
		t.Errorf("found %d register calls in the source, %d ops at run time", seen, len(ops))
	}
}

func TestFieldSpecsAreWellFormed(t *testing.T) {
	kinds := []ciphertools.Kind{ciphertools.KindString, ciphertools.KindInt, ciphertools.KindBool, ciphertools.KindJSON,
		ciphertools.KindEnum, ciphertools.KindList, ciphertools.KindFile}
	names := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	inRange := func(f ciphertools.Field, v string) bool {
		n, err := strconv.Atoi(v)
		return err == nil && (f.Min == nil || n >= *f.Min) && (f.Max == nil || n <= *f.Max)
	}
	for _, op := range ciphertools.Ops() {
		if len(op.Fields) == 0 {
			t.Errorf("%s declares no fields", op.Name)
		}
		seen := map[string]bool{}
		for _, f := range op.Fields {
			at := op.Name + " " + f.Name
			if !names.MatchString(f.Name) || seen[f.Name] {
				t.Errorf("%s: bad or repeated name", at)
			}
			seen[f.Name] = true
			if !slices.Contains(kinds, f.Kind) {
				t.Errorf("%s: unknown kind %q", at, f.Kind)
			}
			if len(f.Description) < 20 || !strings.HasSuffix(f.Description, ".") {
				t.Errorf("%s: the description should be a sentence: %q", at, f.Description)
			}
			listed := f.Kind == ciphertools.KindEnum || f.Kind == ciphertools.KindList
			switch {
			case listed && len(f.Enum) == 0:
				t.Errorf("%s: an %s with no values", at, f.Kind)
			case len(f.Enum) > 0 && !listed && f.Kind != ciphertools.KindInt:
				t.Errorf("%s: Enum on a %s field", at, f.Kind)
			case (f.Min != nil || f.Max != nil) && f.Kind != ciphertools.KindInt:
				t.Errorf("%s: bounds on a %s field", at, f.Kind)
			case f.Min != nil && f.Max != nil && *f.Min > *f.Max:
				t.Errorf("%s: Min above Max", at)
			case f.Kind == ciphertools.KindFile && f.Required:
				t.Errorf("%s: a file can't be required, since a JSON body can't carry one", at)
			}
			for i, v := range f.Enum {
				if slices.Contains(f.Enum[:i], v) || f.Kind == ciphertools.KindInt && !inRange(f, v) {
					t.Errorf("%s: Enum value %q repeated or out of range", at, v)
				}
			}
			if f.Default == "" {
				continue
			}
			var ok bool
			switch f.Kind {
			case ciphertools.KindEnum:
				ok = slices.Contains(f.Enum, f.Default)
			case ciphertools.KindList:
				ok = true
				for _, v := range strings.Split(f.Default, ",") {
					ok = ok && slices.Contains(f.Enum, v)
				}
			case ciphertools.KindInt:
				ok = inRange(f, f.Default) && (len(f.Enum) == 0 || slices.Contains(f.Enum, f.Default))
			case ciphertools.KindBool:
				ok = f.Default == "true" || f.Default == "false"
			case ciphertools.KindJSON:
				ok = json.Valid([]byte(f.Default))
			case ciphertools.KindString:
				ok = true
			}
			if !ok {
				t.Errorf("%s: default %q isn't a valid %s", at, f.Default, f.Kind)
			}
		}
	}
}
