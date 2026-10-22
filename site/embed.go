package site

import "embed"

//go:embed templates
var Templates embed.FS

//go:embed posts
var Posts embed.FS
