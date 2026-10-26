package mailtools

import "embed"

//go:embed templates/*
var Templates embed.FS

//go:embed data/*
var Data embed.FS // seed lists: disposable domains, wildcard patterns, freemail providers, whitelists
