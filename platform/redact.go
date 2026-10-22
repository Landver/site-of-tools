package platform

import (
	"net/url"
	"strings"
)

// redactedParams take a whole pasted URL, which often carries a session token, reset link or signed URL.
var redactedParams = map[string]bool{
	"u":    true, // linktools: every page's input
	"a":    true, // linktools /diff
	"b":    true, // linktools /diff
	"curl": true, // linktools /curl
	"text": true, // linktools /extract
	"v":    true, // linktools /encode — the likeliest place someone pastes a JWT
}

// dnsParams: the DNS tool's own query keys.
var dnsParams = map[string]bool{"name": true, "type": true, "resolver": true}

// redactedName: a DNS ?name= with a path, query, fragment or @ is a pasted URL or email address.
func redactedName(key, rawValue string) bool {
	if strings.ToLower(key) != "name" {
		return false
	}
	v := rawValue
	if dec, err := url.QueryUnescape(rawValue); err == nil {
		v = dec
	}
	return strings.ContainsAny(v, "/?#=@%")
}

// RedactURI blanks redacted values but keeps the path and key names, so the log still shows the request.
func RedactURI(uri string) string {
	if uri == "" {
		return uri
	}
	path, query, ok := strings.Cut(uri, "?")
	if !ok || query == "" {
		return uri
	}
	// /static/ URLs carry AssetVersioner's ?v= hash ("v" is also /encode's key) and no user input.
	if strings.HasPrefix(path, "/static/") {
		return uri
	}
	// Split by hand: url.ParseQuery silently drops a pair with a malformed escape, so "?u=%zz%SECRET"
	// would escape redaction yet still appear in the log line.
	pairs := strings.Split(query, "&")
	changed := false
	// An unencoded pasted URL splits at its own "&"; after a redacted name, non-DNS pairs are its rest.
	pastedURL := false
	for i, pair := range pairs {
		if pair == "" {
			continue
		}
		rawKey, _, hasEq := strings.Cut(pair, "=")
		// A key may itself be escaped; decode best-effort, fall back to raw.
		key := rawKey
		if dec, err := url.QueryUnescape(rawKey); err == nil {
			key = dec
		}
		if !hasEq {
			continue // "?u" carries no value to redact
		}
		lk := strings.ToLower(key)
		switch {
		case redactedParams[lk]:
		case redactedName(key, pair[len(rawKey)+1:]):
			pastedURL = true
		case pastedURL && !dnsParams[lk]:
		default:
			continue
		}
		pairs[i] = rawKey + "=<redacted>"
		changed = true
	}
	if !changed {
		return uri
	}
	return path + "?" + strings.Join(pairs, "&")
}
