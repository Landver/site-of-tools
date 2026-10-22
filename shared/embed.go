// Package shared holds the front-end assets every subdomain uses: base partials and vendored JS/CSS.
package shared

import "embed"

//go:embed templates
var Templates embed.FS

//go:embed all:static
var Static embed.FS
