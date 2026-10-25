package mailtools

import "embed"

// Templates carries every template mail.corpberry.com renders from.
//
//go:embed templates/*
var Templates embed.FS

// Data carries seed lists for disposable domains, wildcard patterns, freemail providers, and whitelists.
//
//go:embed data/*
var Data embed.FS
