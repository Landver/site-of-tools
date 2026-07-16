package botcheck

import "embed"

// Templates holds this tool's templates (the check page + result fragment).
//
//go:embed templates
var Templates embed.FS
