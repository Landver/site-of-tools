package platform

import (
	"net/url"
	"strings"
)

// redactedParams: query keys whose value is replaced before a request is logged
// anywhere. These are the keys tools accept a whole URL on, so on those hosts
// the request URI *is* the visitor's input — and that input routinely carries a
// session token, a password-reset link or a signed URL.
//
// Nothing else in the repo needs this: ip.corpberry.com logs an IP,
// dns.corpberry.com a domain name. link.corpberry.com logs whatever someone
// pasted, which is a different class of data and does not belong in a 30-day
// corpus (tools/linktools/docs/06-security-and-abuse.md §5).
var redactedParams = map[string]bool{
	"u":    true, // linktools: every page's input
	"a":    true, // linktools /diff
	"b":    true, // linktools /diff
	"curl": true, // linktools /curl
	"text": true, // linktools /extract
	"v":    true, // linktools /encode — the likeliest place someone pastes a JWT
}

// RedactURI strips the values of redactedParams from a request URI, keeping the
// path, the key names and every other parameter intact so the corpus still shows
// which endpoint was hit and with what shape of request.
//
// Called once per request in the request logger, before either sink: the slog
// line goes to stdout (captured by Docker on the host, with no TTL at all) and
// the RequestEntry goes to Mongo. Redacting in RequestLog.Record alone would
// leave the stdout copy, which is the longer-lived of the two.
//
// Best-effort by design: a URI that won't parse is truncated at "?" rather than
// logged whole, because an unparseable URI is exactly when a naive logger leaks
// the most.
func RedactURI(uri string) string {
	if uri == "" {
		return uri
	}
	path, query, ok := strings.Cut(uri, "?")
	if !ok || query == "" {
		return uri
	}
	// Static assets carry ?v=<content hash> from AssetVersioner, and "v" is a
	// redacted key because it is /encode's input. Exempting them keeps every
	// static log line readable instead of rewriting the whole site's asset URLs
	// to ?v=<redacted>; nothing user-supplied reaches a /static/ query.
	if strings.HasPrefix(path, "/static/") {
		return uri
	}
	// Hand-split rather than url.Query(). ParseQuery silently DROPS any pair
	// containing a malformed escape and reports an error the caller usually
	// ignores, so a value like "?u=%zz%SECRET" would survive untouched — the
	// pair is invisible to the parser but perfectly visible in the log line.
	// Splitting by hand cannot drop anything, which is the whole requirement
	// here. (Same lesson as tools/linktools/url.go's parser.)
	pairs := strings.Split(query, "&")
	changed := false
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
		if !redactedParams[strings.ToLower(key)] {
			continue
		}
		if !hasEq {
			continue // "?u" carries no value to redact
		}
		pairs[i] = rawKey + "=<redacted>"
		changed = true
	}
	if !changed {
		return uri
	}
	return path + "?" + strings.Join(pairs, "&")
}
