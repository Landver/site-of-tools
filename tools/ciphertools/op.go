// Package ciphertools is cipher.corpberry.com. Everything but handler.go also runs as wasm in the
// visitor's tab (./wasm), so it stays pure Go: no Echo, no platform, no I/O.
package ciphertools

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"maps"
	"math"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Input is one submitted form. url.Values, so a server form and a browser FormData map 1:1.
type Input struct {
	Fields url.Values
	Files  map[string][]byte
}

// Get keeps surrounding whitespace: for a hash input it is the data.
func (in Input) Get(key string) string { return in.Fields.Get(key) }

// InputFromJSON is the Input a form would have made of a flat JSON object, numbers as float64 or json.Number.
func InputFromJSON(obj map[string]any) (Input, error) {
	in := Input{Fields: url.Values{}, Files: map[string][]byte{}}
	for k, v := range obj {
		switch t := v.(type) {
		case string:
			in.Fields.Set(k, t)
		case json.Number:
			if allDigits(strings.TrimPrefix(t.String(), "-")) { // as sent: float64 rounds past 2^53
				in.Fields.Set(k, t.String())
				continue
			}
			f, err := t.Float64()
			if err != nil {
				return in, fmt.Errorf("field %q: %s is out of range", k, t)
			}
			in.Fields.Set(k, strconv.FormatFloat(f, 'f', -1, 64))
		case float64:
			in.Fields.Set(k, strconv.FormatFloat(t, 'f', -1, 64)) // not fmt's "1e+06", which no int field reads
		case bool:
			in.Fields.Set(k, strconv.FormatBool(t))
		case nil:
		default:
			return in, fmt.Errorf("field %q: want a string, number or boolean", k)
		}
	}
	return in, nil
}

// now reads the optional "now" field (unix seconds); absent means the real clock.
func (in Input) now() (time.Time, error) {
	v := strings.TrimSpace(in.Get("now"))
	if v == "" {
		return time.Now(), nil
	}
	sec, err := strconv.ParseInt(v, 10, 64)
	if err != nil {
		return time.Time{}, fmt.Errorf("now: want unix seconds, got %q", v)
	}
	return time.Unix(sec, 0), nil
}

var nowField = Field{Name: "now", Kind: KindInt,
	Description: "Unix time in seconds to use as the current time, e.g. 1700000000; omit it for the real clock."}

// Op is one computation, a form in and a result struct out; the handler and the wasm engine wrap the same registry.
type Op struct {
	Name     string // also the form's data-cipher attribute
	Path     string // POST route of the JSON API
	Page     string // key of the page whose form runs it
	Fragment string // template rendering a successful result
	Fields   []Field
	Heavy    bool // CPU-expensive: stricter server rate limit, never run on a keystroke
	Run      func(Input) (any, error)
}

// ops is filled by each feature file's init.
var ops = map[string]Op{}

func register(op Op) {
	if _, dup := ops[op.Name]; dup {
		panic("ciphertools: duplicate op " + op.Name)
	}
	ops[op.Name] = op
}

// Ops returns every op sorted by name, for a stable route order.
func Ops() []Op {
	return slices.SortedFunc(maps.Values(ops), func(a, b Op) int { return strings.Compare(a.Name, b.Name) })
}

func Lookup(name string) (Op, bool) {
	op, ok := ops[name]
	return op, ok
}

// Run turns a panic into an error: in the browser a panic kills the Go runtime for every later call.
func Run(op Op, in Input) (res any, err error) {
	defer func() {
		if r := recover(); r != nil {
			res, err = nil, fmt.Errorf("internal error: %v", r)
		}
	}()
	return op.Run(in)
}

// MaxFile caps how much of a picked file the worker hands the engine: one byte past it is enough to
// refuse, and running out of Go heap there is fatal. It is hash's limit, the largest; raise them together.
const MaxFile = MaxHashInput

const ErrorFragment = "cipher/error"

const (
	LevelDanger = "danger"
	LevelWarn   = "warn"
	LevelInfo   = "info"
)

type Warning struct {
	Level string `json:"level"`
	Text  string `json:"text"`
}

type Warnings []Warning

func (w *Warnings) add(level, text string) { *w = append(*w, Warning{level, text}) }

// millis rounds to a tenth of a millisecond for the JSON answer.
func millis(d time.Duration) float64 { return math.Round(float64(d.Microseconds())/100) / 10 }

func tookText(d time.Duration) string {
	switch {
	case d < time.Millisecond:
		return "under 1 ms"
	case d < time.Second:
		return fmt.Sprintf("%d ms", d.Milliseconds())
	}
	return fmt.Sprintf("%.2f s", d.Seconds())
}

// Render runs an op and renders its fragment: the browser engine's whole code path.
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

// FragmentTemplates parses the templates alone (wasm, tests): fragments never reach the shells, so stub funcs do.
func FragmentTemplates() (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{
		"asset":      func(string) string { return "" },
		"apexURL":    func() string { return "" },
		"navTools":   func() []struct{} { return nil },
		"navCatalog": func() []struct{} { return nil },
	}).ParseFS(Templates, "templates/*.html")
}
