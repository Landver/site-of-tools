package linktools

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

// Service is the stateless half of this tool: parsing, rebuilding, cleaning,
// unwrapping. It holds no state and opens no connections, so one value is shared
// by every request and a nil check is never needed.
type Service struct{}

func NewService() *Service { return &Service{} }

// Inspector is the handler's view of parsing. Not optional — a nil one is a
// wiring mistake, so Register panics rather than letting it surface per request.
type Inspector interface {
	Parse(raw string) (*Inspection, error)
}

// maxInput bounds what we will parse at all. Well above any real URL; the point
// is that Parse is reachable unauthenticated and its cost should be bounded by
// something other than goodwill.
const maxInput = 64 << 10

// linkableSchemes: schemes we are willing to render as a clickable anchor.
// Everything else is displayed as text. The Inspect page's whole job is showing
// URLs that may be hostile, so this is an allowlist, never a denylist.
var linkableSchemes = map[string]bool{"http": true, "https": true}

// defaultPorts: ports that add nothing when written out.
var defaultPorts = map[string]string{"http": "80", "https": "443", "ftp": "21", "ws": "80", "wss": "443"}

// parseReason is a url.Parse failure without url.Error's own
// `parse "<input>": ` prefix. Every caller shows the message under the box the
// input is still sitting in, and echoing a long URL a second time pushed the
// actual reason (a bad escape, an unclosed "[") off the end of the line.
func parseReason(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	// The package name is Go's, not the reader's: "net/url: invalid control
	// character in URL" says nothing a person needs that "invalid control
	// character in URL" does not.
	if msg := err.Error(); strings.HasPrefix(msg, "net/url: ") {
		return errors.New(strings.TrimPrefix(msg, "net/url: "))
	}
	return err
}

// Pages a pasted input can belong on instead of the one it was pasted into.
const (
	ToolCurl    = "curl"
	ToolExtract = "extract"
)

// WrongTool names the page an input belongs on when it is plainly not one URL:
// a curl command, or text and markup with links in it. "" when it might be a
// URL. Without this the commonest wrong paste, a command copied out of
// DevTools, got "first path segment in URL cannot contain colon" on the page
// people land on first.
//
// It must never refuse a URL, so every test is for something a single URL
// cannot be: markup needs a QUOTED href (a query parameter can be called href,
// as Facebook's share links and click trackers' are), and text needs words
// BEFORE the first link, or a second link that starts after whitespace. A lone
// URL with a raw space in it is still one URL (SharePoint links are pasted
// like that), and so is one carrying another URL unencoded in its query; both
// go on to Inspect, which says what is wrong with them.
func WrongTool(raw string) string {
	t := strings.TrimSpace(raw)
	low := strings.ToLower(t)
	switch {
	case strings.HasPrefix(low, "curl ") || strings.HasPrefix(low, "curl\t") || strings.HasPrefix(low, "curl\n"):
		return ToolCurl
	case strings.Contains(low, "<a ") || strings.Contains(low, `href="`) || strings.Contains(low, "href='") || strings.Contains(t, "](http"):
		return ToolExtract
	}
	first := strings.Index(t, "://")
	switch {
	case first < 0:
		return ""
	case strings.ContainsAny(t[:first], " \t\r\n"):
		return ToolExtract // words before the first link: "see https://…"
	case laterLink.MatchString(t[first+3:]):
		return ToolExtract // a list of links
	}
	return ""
}

// laterLink is a scheme:// that starts after whitespace: the second link in a
// list. One inside a query ("?next=https://…") follows "=", not whitespace.
// templates/live.html carries the same expression.
var laterLink = regexp.MustCompile(`[ \t\r\n][A-Za-z][A-Za-z0-9+.-]*://`)

// Parse takes a URL apart. It never fetches anything.
//
// Deliberately does NOT use url.ParseQuery for the parameter list: that returns
// a map, which loses the original order, and on a malformed escape it returns
// *partial* values alongside an error while silently dropping the offending
// pair (docs/reports/go-url-stdlib-behaviour.md §1). Both behaviours are wrong
// for a tool whose job is showing exactly what is there.
func (s *Service) Parse(raw string) (*Inspection, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("no URL given")
	}
	if len(raw) > maxInput {
		return nil, fmt.Errorf("URL is %d bytes, over the %d KB limit", len(raw), maxInput>>10)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a valid URL: %w", parseReason(err))
	}

	in := &Inspection{Input: raw, Scheme: u.Scheme, Opaque: u.Opaque}
	// Linkable also needs every escape to be well formed. A browser fixes a
	// broken one ("%zz" becomes "%25zz") before following it, so an Open link
	// would go somewhere other than the URL on screen; the parameter's own
	// warning explains the escape.
	in.Linkable = linkableSchemes[strings.ToLower(u.Scheme)] && !hasBadEscape(raw)

	if u.Scheme == "" {
		in.Notes = append(in.Notes, Note{SevWarn, "No scheme",
			"Read as a relative path, so the first part is a folder name, not a host. Add https:// to the front to inspect it as a web address."})
		// "example.com/path" is the commonest paste of all. When adding
		// https:// makes it a URL with a real-looking host, offer exactly that
		// as one click rather than leaving the reader to retype it.
		if alt, err := url.Parse("https://" + raw); err == nil && strings.Contains(alt.Hostname(), ".") {
			in.Absolute = "https://" + raw
		}
	}
	if !in.Linkable && u.Scheme != "" {
		sev, detail := SevInfo, "Shown as text, never as a link."
		switch {
		case strings.EqualFold(u.Scheme, "file"):
			sev = SevWarn
			detail = "A file: URL opens a file on the visitor's own computer. It is shown as text and is never rendered as a clickable link."
		case isDangerousScheme(u.Scheme):
			sev = SevFail
			detail = "This scheme executes rather than navigates. It is shown as text and is never rendered as a clickable link."
		}
		in.Notes = append(in.Notes, Note{sev, "Scheme is " + u.Scheme + ", not http(s)", detail})
	}

	// WrongTool lets a lone URL with a raw space through, so say what is
	// wrong with it here. SharePoint and file-name links arrive like this.
	if strings.ContainsAny(raw, " \t") {
		in.Notes = append(in.Notes, Note{SevWarn, "Unencoded spaces",
			"A URL cannot contain a raw space. A browser sends each one as %20, but in an email or a chat message the link usually stops at the first space. Replace them with %20 before sharing it."})
	}

	s.describeHost(in, u)
	s.describePath(in, u)

	// Query. Hand-split so order, repeats and broken escapes all survive.
	in.Params = parsePairs(u.RawQuery, true)
	// The fragment check below has always existed; the same token in the query
	// string went unremarked, though the query is the half that reaches the
	// server, its logs and every Referer. A warning, not a failure: presigned
	// URLs and magic links carry one on purpose. The point is to treat the URL
	// as a password, not to call it wrong.
	if keys := secretishNames(in.Params); len(keys) > 0 {
		in.Notes = append(in.Notes, Note{SevWarn, "Credentials in the query string",
			strings.Join(keys, ", ") + " looks like a token or a session. A query string reaches the server and its logs, stays in browser history, and can leak to other sites in the Referer header: share this URL as you would a password."})
	}
	if strings.Contains(u.RawQuery, ";") && !strings.Contains(u.RawQuery, "&") &&
		strings.Count(u.RawQuery, ";") >= 1 && len(in.Params) == 1 {
		in.Notes = append(in.Notes, Note{SevWarn, "Semicolon separators",
			"This query separates pairs with ';', which most modern servers no longer accept. It is shown as a single parameter because that is how a server would now read it."})
	}

	// Fragment. Both hosted parsers surveyed discard everything after '#'
	// (docs/reports/), which hides an OAuth implicit-flow access token
	// completely. u.Fragment is already decoded, so re-read the raw tail.
	if frag := rawFragment(raw); frag != "" {
		in.Fragment = u.Fragment
		if strings.Contains(frag, "=") {
			in.FragParams = parsePairs(frag, true)
			if containsSecretish(in.FragParams) {
				in.Notes = append(in.Notes, Note{SevFail, "A token in the fragment",
					"Browsers never send the fragment to a server, but they keep it in history, and anything that logs a full URL keeps it too."})
			}
		}
	}

	// A mail-gateway wrapper names its real destination inside itself, and
	// Inspect's card for it ("This is a … wrapper") was written but never fed:
	// nothing set these fields, so a Safe Links URL pasted here got no hint,
	// and Diff's "unwrapped target" row could never appear either.
	if target, name, partial, ok := unwrapAll(raw); ok && !partial {
		in.Unwrapped, in.Wrapper = target, name
	}

	in.Canonical = canonicalise(u)
	return in, nil
}

// describeHost fills in the host fields and the two host-shaped findings that
// matter: IDN homographs, and userinfo used to disguise the real host.
func (s *Service) describeHost(in *Inspection, u *url.URL) {
	in.Host = u.Hostname()
	in.Port = u.Port()
	if in.Port != "" && defaultPorts[strings.ToLower(u.Scheme)] == in.Port {
		in.DefaultPort = true
	}
	if u.User != nil {
		in.User = u.User.Username()
		_, in.HasPass = u.User.Password()
		in.Notes = append(in.Notes, Note{SevFail, "Credentials before the host",
			fmt.Sprintf("Everything before the @ is a username, not the destination. This URL goes to %s.", in.Host)})
	}
	if in.Host == "" {
		return
	}

	ascii, errA := idna.ToASCII(in.Host)
	uni, errU := idna.ToUnicode(in.Host)
	if errA == nil {
		in.HostASCII = ascii
	}
	if errU == nil {
		in.HostUnicode = uni
	}
	if in.HostASCII != "" && in.HostUnicode != "" && in.HostASCII != in.HostUnicode {
		in.Notes = append(in.Notes, Note{SevWarn, "Internationalised domain name",
			fmt.Sprintf("Displays as %s; DNS looks it up as %s. Check every letter before you trust it.", in.HostUnicode, in.HostASCII)})
	}
	if label, scripts := mixedScriptLabel(in.HostUnicode); label != "" {
		in.Notes = append(in.Notes, Note{SevFail, "Mixed scripts in one label",
			fmt.Sprintf("The label %q mixes %s. Domains that mix writing systems within a single label are the standard shape of a homograph attack.", label, strings.Join(scripts, " and "))})
	}
	if ip := net.ParseIP(in.Host); ip != nil {
		in.Notes = append(in.Notes, Note{SevInfo, "Host is an IP address", "No DNS lookup is involved."})
	} else if addr, ok := numericIPv4(in.Host); ok {
		in.Notes = append(in.Notes, Note{SevWarn, "Host is an IP address in disguise",
			fmt.Sprintf("Browsers read %s as the IPv4 address %s. Writing an address as one number, in hex or in octal is a common way to hide where a link goes.", in.Host, addr)})
	}
}

// numericIPv4 reads a host the way inet_aton does, which is the way browsers
// do: one to four parts, each decimal, 0x hex or 0-prefixed octal, the last
// filling the bytes that remain. "2130706433", "0x7f000001", "0177.1" and
// "127.1" are all 127.0.0.1. A dotted quad of plain decimals is excluded:
// net.ParseIP already reads that as the address it plainly is.
func numericIPv4(h string) (string, bool) {
	if h == "" || net.ParseIP(h) != nil {
		return "", false
	}
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return "", false
	}
	vals := make([]uint64, len(parts))
	for i, p := range parts {
		base := 10
		switch {
		case len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X"):
			base, p = 16, p[2:]
		case len(p) > 1 && p[0] == '0':
			base, p = 8, p[1:]
		}
		v, err := strconv.ParseUint(p, base, 32)
		if err != nil {
			return "", false
		}
		vals[i] = v
	}
	var ip uint64
	last := len(vals) - 1
	for i := 0; i < last; i++ {
		if vals[i] > 255 {
			return "", false
		}
		ip |= vals[i] << (8 * (3 - i))
	}
	if vals[last] >= 1<<(8*(4-last)) {
		return "", false
	}
	ip |= vals[last]
	return fmt.Sprintf("%d.%d.%d.%d", ip>>24, ip>>16&255, ip>>8&255, ip&255), true
}

// hasBadEscape reports a "%" not followed by two hex digits.
func hasBadEscape(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && (i+2 >= len(s) || !isHexDigit(s[i+1]) || !isHexDigit(s[i+2])) {
			return true
		}
	}
	return false
}

// describePath splits the path into segments and resolves dot segments.
//
// Works on EscapedPath, not Path: url.URL.Path has already percent-decoded %2F
// into a real slash, so splitting it turns one segment into two
// (docs/reports/go-url-stdlib-behaviour.md §5). path.Clean is wrong here for the
// same reason, plus it drops RFC 3986's trailing slash and maps "" to ".".
func (s *Service) describePath(in *Inspection, u *url.URL) {
	esc := u.EscapedPath()
	in.Path = esc
	if esc == "" || esc == "/" {
		return
	}
	parts := strings.Split(strings.TrimPrefix(esc, "/"), "/")
	for i, p := range parts {
		dec, err := url.PathUnescape(p)
		if err != nil {
			dec = p
		}
		in.Segments = append(in.Segments, Segment{Index: i + 1, Raw: p, Decoded: dec})
	}
	if resolved := removeDotSegments(esc); resolved != esc {
		in.Notes = append(in.Notes, Note{SevInfo, "Path contains . or .. segments",
			fmt.Sprintf("A server resolves this to %s before doing anything else.", resolved)})
	}
	for _, seg := range in.Segments {
		if strings.Contains(strings.ToLower(seg.Raw), "%2f") {
			in.Notes = append(in.Notes, Note{SevWarn, "Encoded slash in a path segment",
				"%2F inside a segment is a literal slash in that segment's name, not a separator. Decoding it before splitting would silently change the path."})
			break
		}
	}
}

// parsePairs splits a query or fragment into ordered Params.
//
// The whole point of hand-rolling this: order, repeats, valueless keys and
// broken escapes all survive, and nothing is dropped.
func parsePairs(raw string, enrich bool) []Param {
	if raw == "" {
		return nil
	}
	seen := map[string]bool{}
	var out []Param
	for i, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		p := Param{Index: i + 1}
		rawKey, rawVal, hasEq := strings.Cut(pair, "=")
		p.Valueless = !hasEq

		p.Key = decodeOrRaw(rawKey, &p.Warn, "key")
		if p.Key != rawKey {
			p.RawKey = rawKey
		}
		p.Value = decodeOrRaw(rawVal, &p.Warn, "value")
		if p.Value != rawVal {
			p.RawValue = rawVal
		}
		if seen[p.Key] {
			p.Repeat = true
		}
		seen[p.Key] = true

		if enrich {
			enrichParam(&p, rawVal)
		}
		out = append(out, p)
	}
	return out
}

// decodeOrRaw percent-decodes s, keeping the raw text and recording a warning
// when the escape is malformed.
//
// url.QueryUnescape returns the EMPTY STRING on error, not the original
// (docs/reports/go-url-stdlib-behaviour.md §2). Taking its return value blindly
// turns "?bad=%zz" into "?bad=", which looks like a real, empty value.
func decodeOrRaw(s string, warn *string, what string) string {
	dec, err := url.QueryUnescape(s)
	if err != nil {
		if *warn == "" {
			*warn = fmt.Sprintf("The %s contains a malformed percent-escape (%v). It is shown exactly as written; a server may reject it or read it differently.", what, err)
		}
		return s
	}
	if !utf8.ValidString(dec) {
		if *warn == "" {
			*warn = "Decodes to bytes that are not valid UTF-8. Percent-encoding carries no character set, so the original encoding is a guess."
		}
		return s
	}
	return dec
}

// enrichParam adds the value-level findings: the ambiguous '+', delimited
// lists, the decode ladder, and a type.
func enrichParam(p *Param, rawVal string) {
	// The '+' ambiguity. In a query '+' means space; in base64 it is a real
	// character. calcbe and jsonutilities return opposite answers for "a+b" on
	// the same input and neither says so (docs/reports/). Show both readings
	// rather than choosing one.
	if strings.Contains(rawVal, "+") && looksBase64(strings.ReplaceAll(rawVal, "%3D", "=")) {
		p.AltValue = rawVal
		p.Warn = "'+' means a space in a query but is a real character in base64. This value looks like base64, so both readings are shown."
	}
	if d, list := splitList(p.Value); d != "" {
		p.Delimiter, p.List = d, list
	}
	// Name the rule that would strip this parameter, so Inspect can mark a
	// known tracker without Clean being involved — both read one table, which
	// is what makes the two pages agree. This call was missing entirely, so
	// Param.Tracking was never set and inspect.html's "tracker" badge had never
	// rendered once. Global rules only, for the reason on TrackingRuleFor: a
	// key alone cannot tell ref=facebook from ref=main.
	p.Tracking = TrackingRuleFor(p.Key)
	p.Layers = decodeLadder(p.Value)
	p.Kind = classify(p.Value)
	p.Nested = nestedLink(p)
}

// nestedLink is the http(s) URL a parameter carries, once decoded: the value
// itself, or the last rung of its ladder. A redirect= that was encoded twice
// used to show its still-encoded form as the value, with the readable link
// folded away under "decodes further" and nothing to do with it there.
func nestedLink(p *Param) string {
	cand := p.Value
	if len(p.Layers) > 0 {
		cand = p.Layers[len(p.Layers)-1].Value
	}
	u, err := url.Parse(cand)
	if err != nil || u.Host == "" || !linkableSchemes[strings.ToLower(u.Scheme)] {
		return ""
	}
	return cand
}

// splitList recognises a delimited list. The delimiter is returned so the page
// can name it: "Smith,John" is one value containing a comma, not two values,
// and only the reader can tell which.
func splitList(v string) (string, []string) {
	if len(v) < 3 || strings.Contains(v, " ") {
		return "", nil
	}
	for _, d := range []string{",", "|", ";"} {
		if !strings.Contains(v, d) {
			continue
		}
		parts := strings.Split(v, d)
		if len(parts) < 2 {
			continue
		}
		for _, p := range parts {
			if p == "" {
				return "", nil // trailing/doubled delimiter: probably not a list
			}
		}
		return d, parts
	}
	return "", nil
}

// mixedScriptLabel returns the first host label mixing writing systems, with the
// scripts found. This is the homograph tell, and idna exposes no script data, so
// it comes from the stdlib's own range tables.
func mixedScriptLabel(host string) (string, []string) {
	if host == "" {
		return "", nil
	}
	checked := map[string]*unicode.RangeTable{
		"Latin": unicode.Latin, "Cyrillic": unicode.Cyrillic, "Greek": unicode.Greek,
		"Han": unicode.Han, "Arabic": unicode.Arabic, "Hebrew": unicode.Hebrew,
	}
	for _, label := range strings.Split(host, ".") {
		var found []string
		for name, tbl := range checked {
			for _, r := range label {
				if unicode.Is(tbl, r) {
					found = append(found, name)
					break
				}
			}
		}
		if len(found) > 1 {
			sortStrings(found)
			return label, found
		}
	}
	return "", nil
}

// removeDotSegments implements RFC 3986 §5.2.4 over the ESCAPED path.
//
// path.Clean cannot be used: it works on the decoded path, drops the trailing
// slash the RFC preserves after a final "." or "..", and maps "" to ".".
func removeDotSegments(p string) string {
	if p == "" {
		return ""
	}
	lead := strings.HasPrefix(p, "/")
	segs := strings.Split(strings.TrimPrefix(p, "/"), "/")
	out := make([]string, 0, len(segs))
	trailing := false
	for i, s := range segs {
		last := i == len(segs)-1
		switch s {
		case ".":
			trailing = last
		case "..":
			if len(out) > 0 {
				out = out[:len(out)-1]
			}
			trailing = last
		default:
			out = append(out, s)
			trailing = false
		}
	}
	res := strings.Join(out, "/")
	if lead {
		res = "/" + res
	}
	// RFC 3986: a path ending in "." or ".." resolves to one ending in "/".
	if trailing && !strings.HasSuffix(res, "/") {
		res += "/"
	}
	return res
}

// canonicalise applies the lossless normalisations only: lowercase scheme and
// host, drop a default port, resolve dot segments. Stripping parameters is
// Clean's job and is lossy, so it never happens here.
func canonicalise(u *url.URL) string {
	c := *u
	c.Scheme = strings.ToLower(c.Scheme)
	// Never echo a password. url.URL.String() writes userinfo back out
	// verbatim, so copying the struct would reproduce the secret in a field the
	// page renders and the API serialises. Inspection.HasPass is a bool for
	// exactly this reason (docs/06-security-and-abuse.md §8); keep the username,
	// which is the phishing-relevant half, and drop the rest.
	if c.User != nil {
		if name := c.User.Username(); name != "" {
			c.User = url.User(name)
		} else {
			c.User = nil
		}
	}
	if h := c.Hostname(); h != "" {
		host := strings.ToLower(h)
		if ascii, err := idna.ToASCII(host); err == nil {
			host = ascii
		}
		if port := c.Port(); port != "" && defaultPorts[c.Scheme] != port {
			c.Host = net.JoinHostPort(host, port)
		} else if strings.Contains(host, ":") {
			// Hostname() strips an IPv6 literal's brackets, and without them
			// "http://::1/" is not a URL at all; JoinHostPort adds them back
			// in the branch above, so this one must too.
			c.Host = "[" + host + "]"
		} else {
			c.Host = host
		}
	}
	if esc := c.EscapedPath(); esc != "" {
		c.RawPath = removeDotSegments(esc)
		if dec, err := url.PathUnescape(c.RawPath); err == nil {
			c.Path = dec
		}
	}
	return c.String()
}

// rawFragment returns the fragment as written, before any decoding. u.Fragment
// is already decoded, which would corrupt any parameters inside it.
func rawFragment(raw string) string {
	_, frag, ok := strings.Cut(raw, "#")
	if !ok {
		return ""
	}
	return frag
}

var secretishKeys = map[string]bool{
	"access_token": true, "id_token": true, "token": true, "code": true,
	"api_key": true, "apikey": true, "secret": true, "password": true,
	"session": true, "sig": true, "signature": true, "auth": true,
}

func containsSecretish(ps []Param) bool {
	return len(secretishNames(ps)) > 0
}

// secretishNames lists the keys in ps that name a credential and carry a
// value, each once, in order.
func secretishNames(ps []Param) []string {
	var out []string
	seen := map[string]bool{}
	for _, p := range ps {
		k := strings.ToLower(p.Key)
		if secretishKeys[k] && p.Value != "" && !seen[k] {
			seen[k] = true
			out = append(out, p.Key)
		}
	}
	return out
}

func isDangerousScheme(s string) bool {
	switch strings.ToLower(s) {
	case "javascript", "data", "vbscript", "file", "blob":
		return true
	}
	return false
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
