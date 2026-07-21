package botcheck

import "embed"

// Templates holds tool's templates: check page + result fragment.
//
//go:embed templates
var Templates embed.FS
