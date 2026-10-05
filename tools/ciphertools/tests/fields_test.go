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

func TestFieldSpecsMatchTheCode(t *testing.T) {
	registers := regexp.MustCompile(`register\(Op\{Name: "([^"]+)"`)
	fieldVar := regexp.MustCompile(`(\w+) += Field\{Name: "([^"]+)"`)
	reads := regexp.MustCompile(`in\.(?:Get\("([^"]+)"\)|Fields\["([^"]+)"\]|Files\["([^"]+)"\]|(now)\(\))|intField\(in, (\w+)`)
	paths, _ := filepath.Glob("../*.go")
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
	seen := 0
	for p, src := range srcs {
		regs := registers.FindAllStringSubmatch(src, -1)
		if len(regs) == 0 {
			continue
		}
		declared, read := map[string]bool{}, map[string]bool{}
		for _, m := range regs {
			seen++
			op, _ := ciphertools.Lookup(m[1])
			for _, f := range op.Fields {
				declared[f.Name] = true
			}
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
	if ops := len(ciphertools.Ops()); seen != ops {
		t.Errorf("found %d register calls in the source, %d ops at run time", seen, ops)
	}
}

func TestFieldSpecsAreWellFormed(t *testing.T) {
	kinds := []ciphertools.Kind{ciphertools.KindString, ciphertools.KindInt, ciphertools.KindBool, ciphertools.KindJSON,
		ciphertools.KindEnum, ciphertools.KindList, ciphertools.KindFile}
	names := regexp.MustCompile(`^[a-z][a-z0-9_]*$`)
	for _, op := range ciphertools.Ops() {
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
				if slices.Contains(f.Enum[:i], v) {
					t.Errorf("%s: Enum value %q repeated", at, v)
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
				n, err := strconv.Atoi(f.Default)
				ok = err == nil && (f.Min == nil || n >= *f.Min) && (f.Max == nil || n <= *f.Max) &&
					(len(f.Enum) == 0 || slices.Contains(f.Enum, f.Default))
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
