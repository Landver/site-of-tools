package tests

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	gotoken "go/token"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// syntax is the ciphertools package as parsed source, enough to say which
// fields each op's Run reads: in.Get("x"), in.Fields["x"], in.Files["x"],
// intField(in, xField), and the same inside every function or method Run
// hands its Input to. A use of the Input it can't account for is an error,
// so a read can't hide behind a pattern this walker doesn't know.
type syntax struct {
	fset      *gotoken.FileSet
	funcs     map[string][]*ast.FuncDecl // by name
	methods   map[string][]*ast.FuncDecl // by name, any receiver
	fieldVars map[string]string          // package-level Field var → its Name
	runs      map[string]string          // op name → Run function name
	errs      []string
}

func parseCipherPackage(t *testing.T) *syntax {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("..", "*.go")) // go test runs in tools/ciphertools/tests
	if err != nil {
		t.Fatal(err)
	}
	s := &syntax{fset: gotoken.NewFileSet(), funcs: map[string][]*ast.FuncDecl{}, methods: map[string][]*ast.FuncDecl{},
		fieldVars: map[string]string{}, runs: map[string]string{}}
	for _, p := range paths {
		if strings.HasSuffix(p, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(s.fset, p, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv != nil {
					s.methods[d.Name.Name] = append(s.methods[d.Name.Name], d)
					continue
				}
				s.funcs[d.Name.Name] = append(s.funcs[d.Name.Name], d)
				if d.Name.Name == "init" {
					s.registrations(d)
				}
			case *ast.GenDecl:
				s.fieldDecls(d)
			}
		}
	}
	if len(s.funcs) < 50 {
		t.Fatalf("only %d functions found in %v; is the glob rooted right?", len(s.funcs), paths)
	}
	return s
}

func isIdent(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// value is the expression after key: in a composite literal, or nil.
func value(cl *ast.CompositeLit, key string) ast.Expr {
	for _, e := range cl.Elts {
		if kv, ok := e.(*ast.KeyValueExpr); ok && isIdent(kv.Key, key) {
			return kv.Value
		}
	}
	return nil
}

func stringLit(e ast.Expr) (string, bool) {
	bl, ok := e.(*ast.BasicLit)
	if !ok || bl.Kind != gotoken.STRING {
		return "", false
	}
	s, err := strconv.Unquote(bl.Value)
	return s, err == nil
}

func (s *syntax) errorf(pos gotoken.Pos, format string, args ...any) {
	s.errs = append(s.errs, s.fset.Position(pos).String()+": "+fmt.Sprintf(format, args...))
}

// registrations maps each register(Op{Name: …, Run: …}) in an init to its Run.
func (s *syntax) registrations(init *ast.FuncDecl) {
	ast.Inspect(init.Body, func(n ast.Node) bool {
		c, ok := n.(*ast.CallExpr)
		if !ok || !isIdent(c.Fun, "register") || len(c.Args) != 1 {
			return true
		}
		cl, ok := c.Args[0].(*ast.CompositeLit)
		if !ok {
			s.errorf(c.Pos(), "register's argument is not an Op literal")
			return true
		}
		name, ok := stringLit(value(cl, "Name"))
		run, isID := value(cl, "Run").(*ast.Ident)
		if !ok || !isID {
			s.errorf(c.Pos(), "register(Op{…}) without a literal Name and a named Run")
			return true
		}
		s.runs[name] = run.Name
		return true
	})
}

func (s *syntax) fieldDecls(d *ast.GenDecl) {
	if d.Tok != gotoken.VAR {
		return
	}
	for _, spec := range d.Specs {
		vs := spec.(*ast.ValueSpec)
		for i, v := range vs.Values {
			if cl, ok := v.(*ast.CompositeLit); ok && isIdent(cl.Type, "Field") {
				name, ok := stringLit(value(cl, "Name"))
				if !ok {
					s.errorf(cl.Pos(), "Field var %s has no literal Name", vs.Names[i].Name)
				}
				s.fieldVars[vs.Names[i].Name] = name
			}
		}
	}
}

// inputParam is the name of fn's i-th parameter when its type is Input.
func inputParam(fn *ast.FuncDecl, i int) (string, bool) {
	for _, p := range fn.Type.Params.List {
		for _, n := range p.Names {
			if i == 0 {
				return n.Name, isIdent(p.Type, "Input")
			}
			i--
		}
	}
	return "", false
}

type visit struct {
	fn *ast.FuncDecl
	in string
}

// reads adds every field fn reads through its Input parameter in.
func (s *syntax) reads(fn *ast.FuncDecl, in string, out map[string]bool, seen map[visit]bool) {
	if seen[visit{fn, in}] {
		return
	}
	seen[visit{fn, in}] = true
	used := map[*ast.Ident]bool{}
	key := func(e ast.Expr) {
		if k, ok := stringLit(e); ok {
			out[k] = true
		} else {
			s.errorf(e.Pos(), "%s reads a field whose name isn't a string literal", fn.Name.Name)
		}
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.IndexExpr: // in.Fields["x"], in.Files["x"]
			if sel, ok := n.X.(*ast.SelectorExpr); ok && isIdent(sel.X, in) && (sel.Sel.Name == "Fields" || sel.Sel.Name == "Files") {
				used[sel.X.(*ast.Ident)] = true
				key(n.Index)
			}
		case *ast.CallExpr:
			s.call(fn, in, n, key, out, seen, used)
		}
		return true
	})
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == in && !used[id] {
			s.errorf(id.Pos(), "%s uses %s in a way this test can't follow; teach it, or read fields in a way it knows", fn.Name.Name, in)
		}
		return true
	})
}

func (s *syntax) call(fn *ast.FuncDecl, in string, c *ast.CallExpr, key func(ast.Expr), out map[string]bool, seen map[visit]bool, used map[*ast.Ident]bool) {
	if sel, ok := c.Fun.(*ast.SelectorExpr); ok && isIdent(sel.X, in) { // in.Get("x"), in.now()
		used[sel.X.(*ast.Ident)] = true
		if sel.Sel.Name == "Get" {
			key(c.Args[0])
			return
		}
		found := false
		for _, m := range s.methods[sel.Sel.Name] {
			r := m.Recv.List[0]
			if isIdent(r.Type, "Input") && len(r.Names) == 1 {
				found = true
				s.reads(m, r.Names[0].Name, out, seen)
			}
		}
		if !found {
			s.errorf(c.Pos(), "%s calls %s.%s, which this test can't find", fn.Name.Name, in, sel.Sel.Name)
		}
		return
	}
	for i, a := range c.Args {
		if !isIdent(a, in) {
			continue
		}
		used[a.(*ast.Ident)] = true
		var name string
		var decls []*ast.FuncDecl
		switch f := c.Fun.(type) {
		case *ast.Ident:
			name, decls = f.Name, s.funcs[f.Name]
		case *ast.SelectorExpr: // r.encrypt(in, …): every method of that name
			name, decls = f.Sel.Name, s.methods[f.Sel.Name]
		}
		if name == "intField" {
			s.intField(fn, c, out)
			continue
		}
		if len(decls) == 0 {
			s.errorf(c.Pos(), "%s hands %s to a call this test can't follow", fn.Name.Name, in)
		}
		for _, d := range decls {
			p, ok := inputParam(d, i)
			if !ok {
				s.errorf(c.Pos(), "%s hands %s to %s, whose parameter %d isn't an Input", fn.Name.Name, in, name, i)
				continue
			}
			s.reads(d, p, out, seen)
		}
	}
}

// intField's field is a package-level Field var, maybe narrowed by a method
// (randomCountField.withMax(maxBatch)).
func (s *syntax) intField(fn *ast.FuncDecl, c *ast.CallExpr, out map[string]bool) {
	found := false
	ast.Inspect(c.Args[1], func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			if name, ok := s.fieldVars[id.Name]; ok {
				out[name], found = true, true
			}
		}
		return true
	})
	if !found {
		s.errorf(c.Pos(), "%s calls intField with no package-level Field var", fn.Name.Name)
	}
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// The code is the truth: every key an op's Run reads must be in its Fields,
// and every field in its Fields must be read. MCP generates its tool schemas
// from Fields, so drift either way is an argument the tool lies about.
func TestFieldSpecsMatchTheCode(t *testing.T) {
	s := parseCipherPackage(t)
	ops := ciphertools.Ops()
	if len(s.runs) != len(ops) {
		t.Errorf("found %d register calls in the source, %d ops at run time", len(s.runs), len(ops))
	}
	for _, op := range ops {
		run := s.runs[op.Name]
		if len(s.funcs[run]) != 1 {
			t.Errorf("%s: no single Run function %q in the source", op.Name, run)
			continue
		}
		fn := s.funcs[run][0]
		in, ok := inputParam(fn, 0)
		if !ok {
			t.Errorf("%s: %s doesn't take an Input first", op.Name, run)
			continue
		}
		read := map[string]bool{}
		s.reads(fn, in, read, map[visit]bool{})
		declared := map[string]bool{}
		for _, f := range op.Fields {
			declared[f.Name] = true
		}
		for _, k := range sortedKeys(read) {
			if !declared[k] {
				t.Errorf("%s reads %q, which its Fields don't declare", op.Name, k)
			}
		}
		for _, k := range sortedKeys(declared) {
			if !read[k] {
				t.Errorf("%s declares %q, which its Run never reads", op.Name, k)
			}
		}
	}
	for _, e := range s.errs {
		t.Error(e)
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
