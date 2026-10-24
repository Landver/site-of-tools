//go:build js && wasm

package main

import (
	"bytes"
	"net/url"
	"strings"
	"syscall/js"

	"github.com/Landver/site-of-tools/tools/mailtools"
)

func main() {
	t, err := mailtools.FragmentTemplates()
	if err != nil {
		js.Global().Set("mailInitError", err.Error())
		return
	}
	js.Global().Set("mailRun", js.FuncOf(func(_ js.Value, args []js.Value) any {
		if len(args) < 3 {
			return `<div class="alert-error" role="alert">invalid arguments to mail engine</div>`
		}
		op := args[0].String()
		fields := args[1]
		files := args[2]

		var fileBytes []byte
		if files.Length() > 0 {
			f := files.Index(0)
			fileVal := f.Index(1)
			fileBytes = make([]byte, fileVal.Get("length").Int())
			js.CopyBytesToGo(fileBytes, fileVal)
		}

		fieldVals := url.Values{}
		for i := range fields.Length() {
			p := fields.Index(i)
			fieldVals.Add(p.Index(0).String(), p.Index(1).String())
		}

		switch op {
		case "dmarc":
			if len(fileBytes) > 0 {
				html, _ := mailtools.RenderDMARC(t, bytes.NewReader(fileBytes))
				return html
			}
			xmlStr := strings.TrimSpace(fieldVals.Get("xml"))
			if xmlStr == "" {
				return `<div class="alert-error" role="alert">Please upload a .xml or .xml.gz DMARC report, or paste raw XML text.</div>`
			}
			html, _ := mailtools.RenderDMARC(t, strings.NewReader(xmlStr))
			return html
		case "bimi":
			var raw string
			if len(fileBytes) > 0 {
				raw = string(fileBytes)
			} else {
				raw = strings.TrimSpace(fieldVals.Get("svg"))
			}
			if raw == "" {
				return `<div class="alert-error" role="alert">Please choose an SVG file or paste raw SVG markup.</div>`
			}
			html, _ := mailtools.RenderBIMI(t, raw)
			return html
		case "arc":
			headers := strings.TrimSpace(fieldVals.Get("headers"))
			if headers == "" {
				return `<div class="alert-error" role="alert">Please paste email headers containing ARC tags.</div>`
			}
			html, _ := mailtools.RenderARC(t, headers)
			return html
		default:
			return `<div class="alert-error" role="alert">Unknown mail operation: ` + op + `</div>`
		}
	}))
	select {}
}
