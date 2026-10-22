package ciphertools

import "embed"

//go:embed templates
var Templates embed.FS // page shells and result fragments, run by the server and the wasm engine alike
