package ciphertools

import "embed"

// Templates holds page shells and result fragments, run by the server and the wasm engine alike.
//
//go:embed templates
var Templates embed.FS
