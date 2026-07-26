package site

import "embed"

// Templates: apex (corpberry.com) templates.
//
//go:embed templates
var Templates embed.FS

// Posts: blog markdown (site/posts/*.md). Embedded in prod; main serves the
// disk dir in dev instead (platform.SubFS).
//
//go:embed posts
var Posts embed.FS
