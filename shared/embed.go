// Package shared holds cross-cutting front-end assets every subdomain uses:
// base template partials + vendored htmx/Alpine/Tailwind output. Tool-specific
// stuff stays in that tool's own package.
package shared

import "embed"

// Templates holds shared base partials (head/header/footer).
//
//go:embed templates
var Templates embed.FS

// Static holds shared CSS + JS served at /static.
//
//go:embed all:static
var Static embed.FS
