package ciphertools

import "embed"

// Templates: page shells + result fragments. The same files are executed by the
// server (no-JS path) and by the wasm engine in the browser (FragmentTemplates).
//
//go:embed templates
var Templates embed.FS
