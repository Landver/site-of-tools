//go:build js && wasm

// Command wasm is the in-browser engine for cipher.corpberry.com: the
// ciphertools ops compiled to WebAssembly, run inside a Web Worker by
// shared/static/js/cipher-worker.js. Build: make wasm.
//
// It exposes one function, cipherRun(op, fields, files) -> html, and renders the
// result with the very templates the server uses, so there is no second
// implementation of anything to drift out of step (docs/02-build-plan.md).
package main

import (
	"net/url"
	"syscall/js"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func main() {
	t, err := ciphertools.FragmentTemplates()
	if err != nil {
		// A template that fails to parse is a build bug; say so where the page
		// can show it rather than dying silently.
		js.Global().Set("cipherInitError", err.Error())
		return
	}
	js.Global().Set("cipherRun", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) != 3 {
			return "cipherRun: want (op, fields, files)"
		}
		return ciphertools.Render(t, args[0].String(), input(args[1], args[2]))
	}))
	select {} // keep the runtime alive for later calls
}

// input converts the worker's message — fields as [[name, value], …] and files
// as [[name, Uint8Array], …] — into the Input every op takes.
func input(fields, files js.Value) ciphertools.Input {
	in := ciphertools.Input{Fields: url.Values{}, Files: map[string][]byte{}}
	for i := 0; i < fields.Length(); i++ {
		p := fields.Index(i)
		in.Fields.Add(p.Index(0).String(), p.Index(1).String())
	}
	for i := 0; i < files.Length(); i++ {
		p := files.Index(i)
		src := p.Index(1)
		b := make([]byte, src.Get("length").Int())
		js.CopyBytesToGo(b, src)
		in.Files[p.Index(0).String()] = b
	}
	return in
}
