package mailtools

import "embed"

// Templates carries every template mail.corpberry.com renders from.
//
//go:embed templates/*
var Templates embed.FS
