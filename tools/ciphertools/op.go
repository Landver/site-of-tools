// Package ciphertools is cipher.corpberry.com: JWT, hashes, HMAC, password
// hashing, encryption, keys, certificates, TOTP, random values and byte
// encodings.
//
// The package is built twice. Natively it sits behind handler.go and answers the
// JSON API; compiled to WebAssembly (./wasm) the same code runs inside the
// visitor's browser, so nothing they paste has to leave the tab. Everything here
// except handler.go must therefore stay pure Go — no Echo, no platform, no I/O —
// or the wasm build breaks. See docs/02-build-plan.md.
package ciphertools

import (
	"bytes"
	"fmt"
	"html/template"
	"net/url"
	"sort"
	"strings"
	"time"
)

// Input is one submitted form: its fields and any uploaded files, keyed by field
// name. url.Values rather than a struct so the server (c.Request().Form) and the
// browser (a JS FormData) hand over the same shape without translation.
type Input struct {
	Fields url.Values
	Files  map[string][]byte
}

// Get returns a field with surrounding whitespace kept — callers decide what to
// trim, because for a hash input the whitespace IS the data.
func (in Input) Get(key string) string { return in.Fields.Get(key) }

// now reads the optional "now" field (unix seconds) so an API caller can ask
// "was this token valid at T", and tests are deterministic. Absent means the
// real clock.
func (in Input) now() (time.Time, error) {
	v := strings.TrimSpace(in.Get("now"))
	if v == "" {
		return time.Now(), nil
	}
	var sec int64
	if _, err := fmt.Sscan(v, &sec); err != nil {
		return time.Time{}, fmt.Errorf("now: want unix seconds, got %q", v)
	}
	return time.Unix(sec, 0), nil
}

// Op is one computation: a form in, a result struct out. The registry below is
// the whole feature set; the server handler and the wasm entrypoint are both a
// few lines wrapped around it.
type Op struct {
	// Name is the op's key, also the form's data-cipher attribute.
	Name string
	// Path is the POST route of the JSON API.
	Path string
	// Page is the key of the page this op's form lives on (handler.go).
	Page string
	// Fragment is the template that renders a successful result.
	Fragment string
	// Heavy marks CPU-expensive ops (password hashing, RSA keygen): stricter
	// server rate limit, and never run on a keystroke in the browser.
	Heavy bool
	Run   func(Input) (any, error)
}

// ops is filled by each feature file's init, so adding a page never touches a
// central list.
var ops = map[string]Op{}

func register(op Op) {
	if _, dup := ops[op.Name]; dup {
		panic("ciphertools: duplicate op " + op.Name)
	}
	ops[op.Name] = op
}

// Ops returns every registered op, sorted by name for stable route order.
func Ops() []Op {
	out := make([]Op, 0, len(ops))
	for _, op := range ops {
		out = append(out, op)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Lookup finds an op by name.
func Lookup(name string) (Op, bool) {
	op, ok := ops[name]
	return op, ok
}

// Run executes an op, turning a panic into an error. In the browser a panic
// would kill the Go runtime and leave every later call answering "Go program has
// already exited", so no input may be allowed to take the engine down.
func Run(op Op, in Input) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("internal error: %v", r)
		}
	}()
	return op.Run(in)
}

// MaxFile is the most of a picked file the in-browser engine reads: the worker
// hands an op at most MaxFile+1 bytes of it, one past the limit, which is all an
// op needs to refuse it. Read whole, a disk image was copied into the Go heap,
// and running out of memory there is a fatal error no recover catches, so the
// engine was gone until a reload. It is the largest limit any op has (hash's);
// raise it with that one.
const MaxFile = MaxHashInput

// ErrorFragment renders a failed op.
const ErrorFragment = "cipher/error"

// Render runs an op and renders its result fragment — the browser's whole code
// path, and the server's no-JS path uses the same templates. Returns HTML.
func Render(t *template.Template, name string, in Input) string {
	op, ok := Lookup(name)
	if !ok {
		return renderError(t, fmt.Errorf("unknown operation %q", name))
	}
	res, err := Run(op, in)
	if err != nil {
		return renderError(t, err)
	}
	var b bytes.Buffer
	if err := t.ExecuteTemplate(&b, op.Fragment, map[string]any{"Result": res, "Op": op.Name}); err != nil {
		return renderError(t, fmt.Errorf("render: %w", err))
	}
	return b.String()
}

func renderError(t *template.Template, err error) string {
	var b bytes.Buffer
	if t.ExecuteTemplate(&b, ErrorFragment, map[string]any{"Error": err.Error()}) != nil {
		return "<p>" + template.HTMLEscapeString(err.Error()) + "</p>"
	}
	return b.String()
}

// FragmentTemplates parses this package's templates on their own, for the wasm
// engine and for tests. The page shells in the same files call the shared
// partials and the engine's nav funcs; html/template only resolves a
// {{template}} call when it is executed, and fragments never reach the shells,
// so stub funcs are enough to get through the parse.
func FragmentTemplates() (*template.Template, error) {
	stubs := template.FuncMap{
		"asset":    func(string) string { return "" },
		"apexURL":  func() string { return "" },
		"navTools": func() []struct{} { return nil },
	}
	return template.New("").Funcs(stubs).ParseFS(Templates, "templates/*.html")
}
