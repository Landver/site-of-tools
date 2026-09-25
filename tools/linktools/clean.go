package linktools

import (
	"encoding/base64"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"slices"
	"strings"
)

// Cleaning and unwrapping — A4 and A16. Both are pure string work and neither
// opens a connection, ever.
//
// THE INVARIANT, which is docs/04-short-links.md §9 and the reason the two
// operations are separate functions rather than one option:
//
//   - CLEANING ONLY EVER DELETES QUERY PARAMETERS. It never rewrites scheme,
//     host, port, path or fragment. This file achieves that structurally: Clean
//     cuts the raw input into prefix / query / fragment, rebuilds only the
//     query out of the surviving pairs' ORIGINAL BYTES, and splices the other
//     two back untouched. Nothing is re-encoded, so a percent-escape a
//     signature covers survives byte for byte.
//
//   - UNWRAPPING DOES CHANGE THE HOST. That makes it a separate, explicitly
//     requested operation — CleanOptions.Unwrap, never implied by `clean: true`
//     on the short-link create path — and ANYTHING UNWRAPPED MUST BE RE-PARSED
//     AND RE-VALIDATED BY THE CALLER before it is stored or rendered as a link.
//     Unwrapping an attacker-supplied Safe Links wrapper is exactly how a
//     file:// or an internal host gets smuggled past a validation that ran on
//     the wrapper. short.go's validateTarget is that second check.
//
// Rule tables live in rules.go; this file is the machinery that reads them.
// Wrapper formats come from docs/reports/wrapper-formats.md, all of them
// executed against a stated input before being written down.

// Bounds. Every one of these is reachable unauthenticated, so the cost of a
// hostile input is capped by arithmetic rather than by goodwill.
const (
	maxUnwrapHops  = 5 // Safe Links around urldefense is routine where both are deployed
	maxDecodeRungs = 4 // decode-once-then-test, with room for a genuine double encode
)

// CleanOptions are the three choices the page offers.
//
// Sort is OFF by default and stays that way. Reordering a query makes two URLs
// comparable and breaks every signed one whose signature covers the literal
// string — Azure SAS, CloudFront policies, any hand-rolled HMAC. A5 says the
// same thing (docs/01-feature-inventory.md#a5) and it is the one option here
// whose default is a correctness decision rather than a taste one.
//
// StripAffiliate is OFF by default for a different reason: stripping gclid
// costs an advertiser a data point, stripping an Associates tag takes money
// from whoever wrote the review the user followed. Those are different
// decisions and the second one should be made deliberately.
type CleanOptions struct {
	Sort           bool
	StripAffiliate bool
	Unwrap         bool
}

// Removal is one deleted parameter. The value is echoed back so the deletion is
// reversible, and Rule names the rule that did it: A4 promises the output
// "names every parameter removed and the rule that removed it", which is what
// makes a wrong rule reportable instead of invisible. Why is never empty.
//
// This supersedes the `Removed` sketch in the tracking report §7: the origin
// and class it carried as separate fields are folded into Rule and Why, because
// four fields that must always be read together are one sentence.
type Removal struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Rule  string `json:"rule"`
	Why   string `json:"why"`
}

// CleanResult is the whole answer. Output equals Input byte for byte when
// nothing was removed, which is the cheapest possible proof of the invariant
// above.
type CleanResult struct {
	Input     string    `json:"input"`
	Output    string    `json:"output"`
	Removed   []Removal `json:"removed,omitempty"`
	Unwrapped string    `json:"unwrapped,omitempty"` // set only when Unwrap was asked for and fired
	Wrapper   string    `json:"wrapper,omitempty"`   // which wrapper(s), in order
	Notes     []Note    `json:"notes,omitempty"`
}

// Clean strips the tracking parameters from raw and reports what went.
//
// When opt.Unwrap is set it unwraps FIRST and then cleans the target, because
// cleaning the wrapper's own query would only delete the wrapper's bookkeeping.
// The result carries a warning that the host changed, because it did.
func (s *Service) Clean(raw string, opt CleanOptions) (*CleanResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no URL given")
	}
	if len(raw) > maxInput {
		return nil, fmt.Errorf("URL is %d bytes; the limit is %d", len(raw), maxInput)
	}

	res := &CleanResult{Input: raw}
	work := raw

	if opt.Unwrap {
		target, name, partial, ok := unwrapAll(raw)
		switch {
		case ok && partial:
			res.Wrapper = name
			res.Notes = append(res.Notes, Note{SevWarn, "Destination domain only",
				fmt.Sprintf("This is a %s wrapper. It names the destination domain (%s) and nothing else: the path is a server-side token and cannot be recovered without fetching it.", name, target)})
		case ok:
			res.Unwrapped, res.Wrapper = target, name
			work = target
			res.Notes = append(res.Notes, Note{SevWarn, "Host changed by unwrapping",
				fmt.Sprintf("The %s wrapper was removed, so this no longer points at the same host as the input. Re-check the destination before trusting it; nothing about the wrapper vouched for it.", name)})
		}
	}

	u, err := url.Parse(work)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}
	host := u.Hostname()

	prefix, query, frag, hasQuery, hasFrag := splitParts(work)
	pairs := splitRawPairs(query)

	// Presigned URLs are all-or-nothing. AWS's canonical query string covers
	// every parameter except X-Amz-Signature itself, so deleting ANY parameter
	// invalidates the signature — including a genuine utm_source somebody
	// appended by hand. The only correct behaviour is to touch nothing and say
	// why (tracking report §2).
	if reason, signed := looksSigned(pairs); signed {
		res.Output = work
		res.Notes = append(res.Notes, Note{SevWarn, "Signed URL: nothing removed",
			"This looks like " + reason + ". The signature covers every other parameter, so removing even a real tracking parameter would turn the link into a 403. Nothing was changed."})
		return res, nil
	}

	kept := make([]rawPair, 0, len(pairs))
	var affiliate []string
	for _, p := range pairs {
		if p.key == "" {
			kept = append(kept, p) // "&&" or a stray "&": not ours to tidy
			continue
		}
		r, ok := lookupTracking(p.key, host, opt.StripAffiliate)
		if !ok {
			// Name what the affiliate checkbox would have caught, so the option
			// is discoverable without being on.
			if !opt.StripAffiliate {
				if a, hit := lookupTracking(p.key, host, true); hit && a.Class == ClassAffiliate {
					affiliate = append(affiliate, p.key)
				}
			}
			kept = append(kept, p)
			continue
		}
		res.Removed = append(res.Removed, removalFor(p, r))
	}

	if opt.Sort {
		// Stable, so repeated keys keep their relative order — collapsing those
		// is exactly the bug url.go refuses to have.
		slices.SortStableFunc(kept, func(a, b rawPair) int { return strings.Compare(a.key, b.key) })
		if name, risky := looksSignable(pairs); risky {
			res.Notes = append(res.Notes, Note{SevWarn, "Sorting a signed URL",
				fmt.Sprintf("This URL carries %q, which usually signs the query as written. Sorting reorders it and may produce a 403.", name)})
		}
	}

	newQuery := joinRawPairs(kept)
	out := prefix
	switch {
	case newQuery != "":
		out += "?" + newQuery
	case hasQuery && len(res.Removed) == 0:
		out += "?" // an empty query the user wrote; not ours to drop
	}
	if hasFrag {
		out += "#" + frag
	}
	res.Output = out

	if len(affiliate) > 0 {
		res.Notes = append(res.Notes, Note{SevInfo, "Affiliate parameters left in place",
			fmt.Sprintf("%s pays whoever published this link. It was kept because affiliate stripping is off by default; turn it on to remove it.", strings.Join(affiliate, ", "))})
	}
	if len(res.Removed) == 0 && res.Unwrapped == "" {
		res.Notes = append(res.Notes, Note{SevOK, "Nothing to remove", catalogScope})
	}
	return res, nil
}

// Unwrap recovers the real target from a known wrapper. Offline only: it reads
// the string it was given and never opens a connection, which is the whole
// argument for A16 existing separately from A6 Trace.
//
// Returns ok=false for anything it does not recognise, and for the opaque
// shorteners on purpose — t.co, lnkd.in and bit.ly keep the mapping
// server-side, so there is nothing in the string to recover and claiming
// otherwise would be a lie the UI then has to apologise for.
//
// A partial wrapper (Mimecast) returns its NAME with ok=false: something was
// recognised, but what came out is a bare domain, not a URL. Clean surfaces
// that as a note; a caller of Unwrap must not treat it as a destination.
func (s *Service) Unwrap(raw string) (target string, wrapper string, ok bool) {
	t, name, partial, got := unwrapAll(strings.TrimSpace(raw))
	if !got {
		return "", "", false
	}
	if partial {
		return "", name, false
	}
	return t, name, true
}

// TrackingRuleFor names the rule that would strip key, or "" — the hook url.go's
// parser uses to fill Param.Tracking without importing anything.
//
// GLOBAL RULES ONLY, deliberately. A parameter name carries no information
// about the server that will read it: ref=facebook is a tracker, ref=main picks
// a git branch, ref=1234 is a foreign key, and nothing in the string separates
// them (tracking report §3). So a caller with no host gets the rules that are
// safe on a name alone; Clean, which does know the host, sees the rest.
func TrackingRuleFor(key string) string {
	r, ok := lookupTracking(key, "", false)
	if !ok {
		return ""
	}
	return r.name()
}

func removalFor(p rawPair, r Rule) Removal {
	why := r.Origin + ": " + r.Class.why() + "."
	if r.Note != "" {
		why += " " + r.Note
	}
	return Removal{Key: p.key, Value: p.value, Rule: r.name(), Why: why}
}

// ---------------------------------------------------------------------------
// Query surgery. Everything here works on the ORIGINAL BYTES of each pair.
// ---------------------------------------------------------------------------

// rawPair is one query pair. raw is what was written; key and value are decoded
// copies used only for matching and for display.
//
// parsePairs in url.go cannot be reused here: it returns decoded values, and
// re-encoding a kept pair to put it back would change bytes that a signature
// covers. Its decodeOrRaw IS reused, so the two files agree on what a malformed
// escape means.
type rawPair struct {
	raw   string
	key   string
	value string
}

// splitRawPairs splits a query into pairs, keeping each one's exact text.
// Splits on "&" only: ';' stopped being a separator in Go 1.17 and in most
// servers in 2021, and url.go already reports that as a finding rather than
// quietly honouring it.
func splitRawPairs(query string) []rawPair {
	if query == "" {
		return nil
	}
	parts := strings.Split(query, "&")
	out := make([]rawPair, 0, len(parts))
	for _, part := range parts {
		p := rawPair{raw: part}
		rawKey, rawVal, _ := strings.Cut(part, "=")
		var ignored string
		p.key = decodeOrRaw(rawKey, &ignored, "key")
		ignored = ""
		p.value = decodeOrRaw(rawVal, &ignored, "value")
		out = append(out, p)
	}
	return out
}

func joinRawPairs(ps []rawPair) string {
	if len(ps) == 0 {
		return ""
	}
	parts := make([]string, len(ps))
	for i, p := range ps {
		parts[i] = p.raw
	}
	return strings.Join(parts, "&")
}

// splitParts cuts raw into the three ranges Clean treats differently. The
// fragment is cut FIRST: a '?' after a '#' belongs to the fragment, and cutting
// the other way round invents a query that is not there.
func splitParts(raw string) (prefix, query, frag string, hasQuery, hasFrag bool) {
	base, frag, hasFrag := strings.Cut(raw, "#")
	prefix, query, hasQuery = strings.Cut(base, "?")
	return prefix, query, frag, hasQuery, hasFrag
}

// looksSigned reports whether the query carries a signature that covers the
// other parameters. Returns the human name of the scheme for the note.
func looksSigned(ps []rawPair) (string, bool) {
	has := make(map[string]bool, len(ps))
	for _, p := range ps {
		k := strings.ToLower(p.key)
		has[k] = true
		switch {
		case strings.HasPrefix(k, "x-amz-"):
			return "an S3 presigned URL (AWS Signature Version 4)", true
		case strings.HasPrefix(k, "x-goog-"):
			return "a Google Cloud Storage signed URL", true
		}
	}
	switch {
	case has["signature"] && has["awsaccesskeyid"]:
		return "an S3 presigned URL (Signature Version 2)", true
	case has["signature"] && (has["key-pair-id"] || has["policy"]):
		return "a CloudFront signed URL", true
	case has["sig"] && has["sv"]:
		return "an Azure Blob SAS URL", true
	}
	return "", false
}

// looksSignable is the weaker check behind the sort warning: a bare signature
// parameter with none of the vendor context looksSigned needs. Removing nothing
// is still safe here, but reordering may not be.
func looksSignable(ps []rawPair) (string, bool) {
	for _, p := range ps {
		switch strings.ToLower(p.key) {
		case "sig", "signature", "hmac", "mac":
			return p.key, true
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Unwrapping.
// ---------------------------------------------------------------------------

// unwrapAll peels nested wrappers. Bounded and cycle-guarded: wrappers nest for
// real (Safe Links around urldefense wherever both products are deployed), and
// a wrapper whose target is itself is a two-line denial of service otherwise.
func unwrapAll(raw string) (target, name string, partial, ok bool) {
	seen := map[string]bool{raw: true}
	cur := raw
	var names []string
	for hop := 0; hop < maxUnwrapHops; hop++ {
		next, w, isPartial, got := unwrapOnce(cur)
		if !got {
			break
		}
		if isPartial {
			names = append(names, w)
			return next, strings.Join(names, " -> "), true, true
		}
		if next == "" || seen[next] {
			break
		}
		names = append(names, w)
		seen[next] = true
		cur, target = next, next
	}
	if target == "" {
		return "", "", false, false
	}
	return target, strings.Join(names, " -> "), false, true
}

// unwrapOnce removes a single layer.
func unwrapOnce(raw string) (target, name string, partial, ok bool) {
	if raw == "" || len(raw) > maxInput {
		return "", "", false, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false, false
	}
	// Every wrapper matching this host+path, tried in turn: one host can carry
	// several shapes (google.<tld> is /url, /amp/ and ?adurl= at once), and the
	// first match is not always the one holding a target.
	for _, w := range wrappersFor(u.Hostname(), u.EscapedPath()) {
		if t, n, p, got := applyWrapper(raw, u, w); got {
			return t, n, p, true
		}
	}
	return "", "", false, false
}

// applyWrapper runs one wrapper rule against an already-parsed URL.
func applyWrapper(raw string, u *url.URL, w Wrapper) (target, name string, partial, ok bool) {
	var candidate string
	switch w.Shape {
	case ShapeParam:
		// Read the PAIR, never regex the tail. The u=…&h=… bug — where a greedy
		// capture appends the shim's own hash to the destination — is the most
		// common failure in this whole genre, and pair-splitting makes it
		// structurally impossible.
		candidate = rawParam(u.RawQuery, w.Params)
	case ShapeBareQuery:
		// href.li and DeviantArt: the target IS the query string, with no
		// parameter name. Running it through a pair parser would cut it at its
		// own first '&'.
		candidate = u.RawQuery
	case ShapePathTail:
		candidate = pathTail(u.EscapedPath())
	case ShapeCustom:
		candidate = raw // the custom decoders below work on the whole URL
	}
	if candidate == "" {
		return "", "", false, false
	}

	switch w.Decode {
	case DecodeNone, DecodePercent:
		target = percentLadder(candidate, url.QueryUnescape)
	case DecodePathPercent:
		target = percentLadder(candidate, url.PathUnescape)
	case DecodeURLDefenseV1:
		target = percentLadder(decodeURLDefenseV1(raw), url.QueryUnescape)
	case DecodeURLDefenseV2:
		target = percentLadder(decodeURLDefenseV2(raw), url.QueryUnescape)
	case DecodeURLDefenseV3:
		target = percentLadder(decodeURLDefenseV3(raw), url.QueryUnescape)
	case DecodeAMPPath:
		target = percentLadder(decodeAMPPath(u), url.QueryUnescape)
	}

	if w.Partial {
		// Mimecast: the answer is a domain, and it must look like one rather
		// than being dressed up as a URL nobody can follow.
		d := strings.ToLower(strings.TrimSpace(firstDecode(candidate)))
		if d == "" || strings.ContainsAny(d, "/ \t") || !strings.Contains(d, ".") {
			return "", "", false, false
		}
		return d, w.Name, true, true
	}
	if target == "" {
		return "", "", false, false
	}
	return target, w.Name, false, true
}

// rawParam returns the first of names present in the query, as RAW bytes.
// Returning the raw value is what lets percentLadder decode exactly once;
// handing back an already-decoded value would eat one rung invisibly.
func rawParam(query string, names []string) string {
	if query == "" {
		return ""
	}
	pairs := splitRawPairs(query)
	for _, want := range names {
		for _, p := range pairs {
			if strings.EqualFold(p.key, want) {
				_, rawVal, _ := strings.Cut(p.raw, "=")
				return rawVal
			}
		}
	}
	return ""
}

// pathTail drops the first path segment, which for Cisco is the ~200-character
// token, and returns the rest as one string.
func pathTail(escPath string) string {
	segs := strings.Split(strings.TrimPrefix(escPath, "/"), "/")
	if len(segs) < 2 {
		return ""
	}
	return strings.Join(segs[1:], "/")
}

// percentLadder is the decode-once-then-test rule, and it is the single most
// important line in this file.
//
// Safe Links percent-encodes the target once, so the target's OWN %20 arrives
// as %2520. Decoding twice turns it into a space and yields a different URL.
// The rule: stop as soon as the result is an absolute http(s) URL, and only go
// again when it is not. Capped, because a nested encode is trivial to build.
func percentLadder(v string, unescape func(string) (string, error)) string {
	cur := strings.TrimSpace(v)
	for i := 0; i < maxDecodeRungs; i++ {
		if absoluteHTTP(cur) {
			return cur
		}
		if !strings.Contains(cur, "%") {
			break
		}
		next, err := unescape(cur)
		if err != nil || next == cur {
			break
		}
		cur = next
	}
	if absoluteHTTP(cur) {
		return cur
	}
	return ""
}

// firstDecode percent-decodes once, for values that are not URLs and so cannot
// use the ladder's absolute-URL stopping test.
func firstDecode(v string) string {
	if dec, err := url.QueryUnescape(v); err == nil {
		return dec
	}
	return v
}

// absoluteHTTP is the gate on every unwrapped value. http(s) only: a wrapper
// whose parameter decodes to file:// or javascript: is an attack, not a
// destination, and the caller re-validates anyway.
func absoluteHTTP(s string) bool {
	if s == "" || len(s) > maxInput {
		return false
	}
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// Proofpoint urldefense. Formats and worked examples: wrapper report §4, every
// one of them executed before it was written down. No API key is needed to
// decode one, despite Proofpoint presenting their URL Decoder API as the way.
// ---------------------------------------------------------------------------

var (
	// v1 and v2 are the documented exception to "read the pair, never regex the
	// tail": the target may contain a raw '&', and the format's own boundary is
	// the next KNOWN parameter, not the next separator. These are Proofpoint's
	// own regexes, from the decoder their engineer published.
	v1Re     = regexp.MustCompile(`[?&]u=(.+?)&k=`)
	v2Re     = regexp.MustCompile(`[?&]u=(.+?)&[dc]=`)
	uTailRe  = regexp.MustCompile(`[?&]u=([^&]*)`)
	v3Re     = regexp.MustCompile(`/v3/__(.+?)__;(.*?)!`)
	oneSlash = regexp.MustCompile(`^([a-zA-Z0-9+.\-]+:/)([^/].*)$`)
)

// decodeURLDefenseV1: percent-decode, then unescape HTML entities. Links pulled
// from mail source arrive with &amp;, and skipping that step ends every target
// at the next parameter.
func decodeURLDefenseV1(raw string) string {
	m := v1Re.FindStringSubmatch(raw)
	if m == nil {
		m = uTailRe.FindStringSubmatch(raw)
	}
	if m == nil {
		return ""
	}
	dec, err := url.QueryUnescape(m[1])
	if err != nil {
		dec = m[1]
	}
	return html.UnescapeString(dec)
}

// decodeURLDefenseV2 substitutes '-' -> '%' and '_' -> '/' first, then
// percent-decodes, then unescapes entities. Order matters: a literal '-' in the
// original was encoded to %2D and arrives as "-2D", so it survives the
// substitution as %2D and comes back out of the percent-decode intact. The same
// trick covers '_' as "-5F".
func decodeURLDefenseV2(raw string) string {
	m := v2Re.FindStringSubmatch(raw)
	if m == nil {
		m = uTailRe.FindStringSubmatch(raw)
	}
	if m == nil {
		return ""
	}
	s := strings.ReplaceAll(m[1], "-", "%")
	s = strings.ReplaceAll(s, "_", "/")
	dec, err := url.QueryUnescape(s)
	if err != nil {
		return ""
	}
	return html.UnescapeString(dec)
}

// v3Alphabet is base64url's, and the run-length token indexes into it: '*X'
// with X='A' means a run of 2, 'B' means 3, and so on.
const v3Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// decodeURLDefenseV3 reverses the munged form:
//
//	https://urldefense.com/v3/__<munged target>__;<base64url>!!<tracking>$
//
// The munged target is the real URL with some characters replaced by '*'
// tokens; those characters, concatenated in order, ARE the base64url payload
// after "__;". So nothing here needs to know which characters Proofpoint
// chooses to munge — the replacement string says. Every attempt to
// reverse-engineer that character set is wasted effort.
//
// Token grammar: '*' consumes one replacement character; '**X' consumes a run
// of len(X)+2. An unmunged URL has an EMPTY replacement string ("__;!!"), which
// is a shape Proofpoint's own samples include, so both regex and base64 must
// tolerate zero length.
func decodeURLDefenseV3(raw string) string {
	m := v3Re.FindStringSubmatch(raw)
	if m == nil {
		return ""
	}
	munged, err := url.PathUnescape(m[1]) // before substitution, not after
	if err != nil {
		munged = m[1]
	}
	// Some v3 rewrites collapse the scheme's "//" to one slash; decoders that
	// do not repair it emit https:/host/… or re-anchor the path against the
	// wrapper host, which is a reported real failure.
	if r := oneSlash.FindStringSubmatch(munged); r != nil {
		munged = r[1] + "/" + r[2]
	}

	// RawURLEncoding rather than appending "==": Go's padded decoders reject
	// over-padding that Python's urlsafe_b64decode tolerates, and unpadded
	// base64url handles all three length cases in one line.
	repl := []byte{}
	if enc := strings.TrimRight(m[2], "="); enc != "" {
		dec, err := base64.RawURLEncoding.DecodeString(enc)
		if err != nil {
			return ""
		}
		repl = dec
	}

	var b strings.Builder
	ri := 0
	for i := 0; i < len(munged); {
		if munged[i] != '*' {
			b.WriteByte(munged[i])
			i++
			continue
		}
		if i+1 < len(munged) && munged[i+1] == '*' {
			if i+2 >= len(munged) {
				return ""
			}
			n := strings.IndexByte(v3Alphabet, munged[i+2])
			if n < 0 || ri+n+2 > len(repl) {
				return ""
			}
			b.Write(repl[ri : ri+n+2])
			ri += n + 2
			i += 3
			continue
		}
		if ri >= len(repl) {
			return ""
		}
		b.WriteByte(repl[ri])
		ri++
		i++
	}
	return b.String()
}

// decodeAMPPath reconstructs the target from a Google AMP viewer URL:
// google.com/amp/s/example.com/page -> https://example.com/page. The "/s/"
// means https; without it, http. This is reconstruction rather than decoding,
// and the UI should say so.
func decodeAMPPath(u *url.URL) string {
	p := u.EscapedPath()
	switch {
	case strings.HasPrefix(p, "/amp/s/"):
		return "https://" + strings.TrimPrefix(p, "/amp/s/")
	case strings.HasPrefix(p, "/amp/"):
		return "http://" + strings.TrimPrefix(p, "/amp/")
	}
	return ""
}

// CleanTargetFunc adapts *Service to the Shortener.CleanTarget seam, so short.go
// never imports the rule tables and clean.go never learns about aliases.
//
// Unwrap is deliberately OFF here. Unwrapping changes the HOST, and the create
// path validates the target before cleaning — so a clean step that could move
// the host would void that validation. Stripping query parameters cannot, which
// is exactly why the two operations are separate everywhere in this package
// (docs/04-short-links.md §9). A wrapped URL is stored as given; the Inspect and
// Clean pages will still reveal its real target on demand.
func CleanTargetFunc(s *Service) func(string) (string, []string, error) {
	return func(raw string) (string, []string, error) {
		res, err := s.Clean(raw, CleanOptions{Unwrap: false})
		if err != nil {
			return "", nil, err
		}
		removed := make([]string, 0, len(res.Removed))
		for _, r := range res.Removed {
			removed = append(removed, r.Key)
		}
		return res.Output, removed, nil
	}
}
