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

// Cleaning only ever deletes query pairs, splicing kept ones back as original bytes so signatures survive.
// Unwrapping changes the host, so callers must re-validate what it returns (short.go's validateTarget).

// Every path here is reachable unauthenticated, so hostile input is capped by arithmetic.
const (
	maxUnwrapHops  = 5 // Safe Links around urldefense is routine where both are deployed
	maxDecodeRungs = 4 // decode-once-then-test, with room for a genuine double encode
)

// CleanOptions defaults matter: Sort is off because reordering breaks signed URLs (SAS, CloudFront, HMAC),
// StripAffiliate is off because dropping a tag takes money from whoever shared the link.
type CleanOptions struct {
	Sort           bool
	StripAffiliate bool
	Unwrap         bool
}

// Removal echoes the deleted value and names the rule, so a wrong rule is reportable instead of invisible.
type Removal struct {
	Key   string `json:"key"`
	Value string `json:"value"`
	Rule  string `json:"rule"`
	Why   string `json:"why"`
}

// CleanResult.Output equals Input byte for byte when nothing was removed.
type CleanResult struct {
	Input     string    `json:"input"`
	Output    string    `json:"output"`
	Removed   []Removal `json:"removed,omitempty"`
	Unwrapped string    `json:"unwrapped,omitempty"` // set only when Unwrap was asked for and fired
	Wrapper   string    `json:"wrapper,omitempty"`   // which wrapper(s), in order
	Notes     []Note    `json:"notes,omitempty"`
}

// Clean strips tracking parameters from raw, unwrapping first when asked so the target gets cleaned.
func (s *Service) Clean(raw string, opt CleanOptions) (*CleanResult, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no URL given")
	}
	if len(raw) > maxInput {
		return nil, fmt.Errorf("URL is %d bytes, over the %d KB limit", len(raw), maxInput>>10)
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
			host := target
			if t, err := url.Parse(target); err == nil && t.Hostname() != "" {
				host = t.Hostname()
			}
			res.Notes = append(res.Notes, Note{SevWarn, "New host after unwrapping",
				fmt.Sprintf("Now pointing at %s. %s did not vouch for it, so check the host before you trust it.", host, name)})
		}
	} else if _, name, _, ok := unwrapAll(raw); ok {
		res.Wrapper = name
		res.Notes = append(res.Notes, Note{SevInfo, "Wrapper left in place",
			fmt.Sprintf("This is a %s link and unwrapping is turned off, so it was cleaned as it stands. The real destination inside it was not touched.", name)})
	}

	u, err := url.Parse(work)
	if err != nil {
		return nil, fmt.Errorf("not a valid URL: %w", parseReason(err))
	}
	// A relative reference is valid and comes back untouched; with no query, say what it is.
	if u.Scheme == "" && u.Host == "" && u.RawQuery == "" {
		res.Notes = append(res.Notes, Note{SevWarn, "Not a whole link",
			"There is no scheme, host or query here, so there was nothing to clean. If you meant to paste a link, paste all of it, starting with https://."})
	}
	// The rules are for web links; only those can pass with nothing to remove.
	isHTTP := strings.EqualFold(u.Scheme, "http") || strings.EqualFold(u.Scheme, "https")
	if u.Scheme != "" && !isHTTP {
		sev, detail := SevInfo, "The rules are written for web links, so this was cleaned as it stands."
		if isDangerousScheme(u.Scheme) {
			sev, detail = SevFail, "This scheme runs code instead of opening a page. There is nothing to clean in it, and it is not safe to share as a link."
		}
		res.Notes = append(res.Notes, Note{sev, "Scheme is " + u.Scheme + ", not http(s)", detail})
	}
	web := isHTTP && u.Host != ""
	host := u.Hostname()

	prefix, query, frag, hasQuery, hasFrag := splitParts(work)
	pairs := splitRawPairs(query)

	// Presigned URLs are all-or-nothing: the signature covers every other parameter, so touch nothing.
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
			// Name what the affiliate option would have caught, so it is discoverable while off.
			if !opt.StripAffiliate {
				if a, hit := lookupTracking(p.key, host, true); hit && a.Class == ClassAffiliate {
					affiliate = append(affiliate, p.key)
				}
			}
			kept = append(kept, p)
			continue
		}
		why := r.Origin + ": " + r.Class.why() + "."
		if r.Note != "" {
			why += " " + r.Note
		}
		res.Removed = append(res.Removed, Removal{Key: p.key, Value: p.value, Rule: r.name(), Why: why})
	}

	if opt.Sort {
		// Stable, so repeated keys keep their relative order.
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
		res.Notes = append(res.Notes, Note{SevInfo, "Affiliate tag kept",
			fmt.Sprintf("Kept: %s pays whoever shared this link. Tick “Also remove affiliate tags” to drop it.", strings.Join(affiliate, ", "))})
	}
	if len(res.Removed) == 0 && res.Unwrapped == "" && web {
		res.Notes = append(res.Notes, Note{SevOK, "Nothing to remove", catalogScope})
	}
	return res, nil
}

// Unwrap recovers a known wrapper's target offline; opaque shorteners (t.co, bit.ly) give ok=false.
// A partial wrapper (Mimecast) returns its name with ok=false: it holds a bare domain, not a URL.
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

// TrackingRuleFor names the rule that would strip key, or "", from global rules only: a name alone
// can't tell ref=facebook (tracker) from ref=main (a branch); Clean, knowing the host, sees the rest.
func TrackingRuleFor(key string) string {
	r, ok := lookupTracking(key, "", false)
	if !ok {
		return ""
	}
	return r.name()
}

// Query surgery: everything below works on the original bytes of each pair.

// rawPair keeps the pair as written; key and value are decoded copies for matching and display only.
type rawPair struct {
	raw   string
	key   string
	value string
}

// splitRawPairs splits on "&" only: ';' stopped being a separator in Go 1.17, and url.go reports it.
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

// splitParts cuts the fragment first: a '?' after '#' belongs to the fragment, not a query.
func splitParts(raw string) (prefix, query, frag string, hasQuery, hasFrag bool) {
	base, frag, hasFrag := strings.Cut(raw, "#")
	prefix, query, hasQuery = strings.Cut(base, "?")
	return prefix, query, frag, hasQuery, hasFrag
}

// looksSigned reports whether a signature covers the other parameters, naming the scheme for the note.
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

// looksSignable is the weaker check behind the sort warning: a bare signature parameter, no vendor context.
func looksSignable(ps []rawPair) (string, bool) {
	for _, p := range ps {
		switch strings.ToLower(p.key) {
		case "sig", "signature", "hmac", "mac":
			return p.key, true
		}
	}
	return "", false
}

// unwrapAll peels nested wrappers, bounded and cycle-guarded: a self-targeting wrapper would loop forever.
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

func unwrapOnce(raw string) (target, name string, partial, ok bool) {
	if raw == "" || len(raw) > maxInput {
		return "", "", false, false
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", "", false, false
	}
	// A host can carry several shapes (google: /url, /amp/, ?adurl=); the first match may hold no target.
	for _, w := range wrappersFor(u.Hostname(), u.EscapedPath()) {
		if t, n, p, got := applyWrapper(raw, u, w); got {
			return t, n, p, true
		}
	}
	return "", "", false, false
}

func applyWrapper(raw string, u *url.URL, w Wrapper) (target, name string, partial, ok bool) {
	var candidate string
	switch w.Shape {
	case ShapeParam:
		// Read the pair, never regex the tail: a greedy capture appends the shim's &h= hash to the target.
		candidate = rawParam(u.RawQuery, w.Params)
	case ShapeBareQuery:
		// href.li and DeviantArt: the whole query is the target; a pair parser would cut it at its first '&'.
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
		// Mimecast yields a bare domain; reject anything that does not look like one.
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

// rawParam returns the RAW value so percentLadder decodes it exactly once; a decoded one eats a rung.
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

// pathTail drops the first segment (Cisco's ~200-character token) and returns the rest.
func pathTail(escPath string) string {
	segs := strings.Split(strings.TrimPrefix(escPath, "/"), "/")
	if len(segs) < 2 {
		return ""
	}
	return strings.Join(segs[1:], "/")
}

// percentLadder decodes only until the value is an absolute http(s) URL: Safe Links encodes once, so the
// target's own %20 arrives as %2520, and one more decode would change the URL.
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

// firstDecode percent-decodes once, for values that are not URLs and so can't use the ladder's stop test.
func firstDecode(v string) string {
	if dec, err := url.QueryUnescape(v); err == nil {
		return dec
	}
	return v
}

// absoluteHTTP gates every unwrapped value: a wrapper decoding to file:// or javascript: is an attack.
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

// Proofpoint urldefense (wrapper report §4); decoding needs no API key despite Proofpoint's docs.

var (
	// v1/v2 regex the tail on purpose: the target may hold a raw '&', so it ends at the next KNOWN
	// parameter. These are the regexes from Proofpoint's own published decoder.
	v1Re     = regexp.MustCompile(`[?&]u=(.+?)&k=`)
	v2Re     = regexp.MustCompile(`[?&]u=(.+?)&[dc]=`)
	uTailRe  = regexp.MustCompile(`[?&]u=([^&]*)`)
	v3Re     = regexp.MustCompile(`/v3/__(.+?)__;(.*?)!`)
	oneSlash = regexp.MustCompile(`^([a-zA-Z0-9+.\-]+:/)([^/].*)$`)
)

// decodeURLDefenseV1 also unescapes HTML entities: links pulled from mail source carry &amp;.
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

// decodeURLDefenseV2 maps '-'->'%' and '_'->'/' before percent-decoding, so a literal '-' ("-2D") survives.
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

// v3Alphabet is base64url's; a run token '**X' indexes into it ('A' = a run of 2, 'B' = 3, ...).
const v3Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// decodeURLDefenseV3 reverses .../v3/__<munged>__;<base64url>!!...: each '*' takes the next replacement
// byte and '**X' a run, so which characters Proofpoint munges never matters. An unmunged URL has an
// empty replacement string ("__;!!"), so the regex and the base64 step must both tolerate zero length.
func decodeURLDefenseV3(raw string) string {
	m := v3Re.FindStringSubmatch(raw)
	if m == nil {
		return ""
	}
	munged, err := url.PathUnescape(m[1]) // before substitution, not after
	if err != nil {
		munged = m[1]
	}
	// Some v3 rewrites collapse the scheme's "//" to one slash; unrepaired, the host is lost.
	if r := oneSlash.FindStringSubmatch(munged); r != nil {
		munged = r[1] + "/" + r[2]
	}

	// RawURLEncoding, not appending "==": Go's padded decoders reject over-padding that Python tolerates.
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

// decodeAMPPath rebuilds google.com/amp/s/example.com/page as https://example.com/page (no /s/ = http).
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

// CleanTargetFunc adapts *Service to Shortener.CleanTarget. Unwrap stays off: the create path validates
// the target before cleaning, and unwrapping changes the host, which would void that validation.
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
