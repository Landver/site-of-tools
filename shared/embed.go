// Package shared holds cross-cutting front-end assets used by every subdomain:
// the base template partials and the vendored htmx/Alpine/Tailwind output.
// Anything specific to a single tool lives in that tool's own package instead.
package shared

import "embed"

// Templates holds the shared base partials (head/header/footer).
//
//go:embed templates
var Templates embed.FS

// Static holds the shared CSS + JS served at /static.
//
//go:embed all:static
var Static embed.FS
