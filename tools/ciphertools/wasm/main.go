//go:build js && wasm

// Command wasm is cipher.corpberry.com's in-browser engine; cipherRun renders with the server's own templates.
package main

import (
	"net/url"
	"syscall/js"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func main() {
	t, err := ciphertools.FragmentTemplates()
	if err != nil {
		js.Global().Set("cipherInitError", err.Error()) // a build bug: say so where the page can show it
		return
	}
	js.Global().Set("cipherMaxFile", ciphertools.MaxFile)
	js.Global().Set("cipherRun", js.FuncOf(func(_ js.Value, args []js.Value) any {
		return ciphertools.Render(t, args[0].String(), input(args[1], args[2]))
	}))
	select {} // keep the runtime alive for later calls
}

// input converts the worker's fields, [[name, value], …], and files, [[name, Uint8Array], …].
func input(fields, files js.Value) ciphertools.Input {
	in := ciphertools.Input{Fields: url.Values{}, Files: map[string][]byte{}}
	for i := range fields.Length() {
		p := fields.Index(i)
		in.Fields.Add(p.Index(0).String(), p.Index(1).String())
	}
	for i := range files.Length() {
		p := files.Index(i)
		b := make([]byte, p.Index(1).Get("length").Int())
		js.CopyBytesToGo(b, p.Index(1))
		in.Files[p.Index(0).String()] = b
	}
	return in
}
