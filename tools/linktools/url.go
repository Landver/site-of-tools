package linktools

import (
	"fmt"
	"net"
	"net/url"
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
		return nil, fmt.Errorf("URL is %d bytes; the limit is %d", len(raw), maxInput)
	}

	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("not a URL: %w", err)
	}

	in := &Inspection{Input: raw, Scheme: u.Scheme, Opaque: u.Opaque}
	in.Linkable = linkableSchemes[strings.ToLower(u.Scheme)]

	if u.Scheme == "" {
		in.Notes = append(in.Notes, Note{SevWarn, "No scheme",
			"This is a relative reference, not an absolute URL. A browser would resolve it against whatever page it appeared on."})
	}
	if !in.Linkable && u.Scheme != "" {
		sev, detail := SevInfo, "Shown as text, never as a link."
		if isDangerousScheme(u.Scheme) {
			sev = SevFail
			detail = "This scheme executes rather than navigates. It is shown as text and is never rendered as a clickable link."
		}
		in.Notes = append(in.Notes, Note{sev, "Scheme is " + u.Scheme + ", not http(s)", detail})
	}

	s.describeHost(in, u)
	s.describePath(in, u)

	// Query. Hand-split so order, repeats and broken escapes all survive.
	in.Params = parsePairs(u.RawQuery, true)
	if strings.Contains(u.RawQuery, ";") && !strings.Contains(u.RawQuery, "&") &&
		strings.Count(u.RawQuery, ";") >= 1 && len(in.Params) == 1 {
		in.Notes = append(in.Notes, Note{SevWarn, "Semicolon separators",
			"This query separates pairs with ';', which Go and most modern servers stopped accepting in 2021 (Go 1.17). It is shown as a single parameter because that is how a server would now read it."})
	}

	// Fragment. Both hosted parsers surveyed discard everything after '#'
	// (docs/reports/), which hides an OAuth implicit-flow access token
	// completely. u.Fragment is already decoded, so re-read the raw tail.
	if frag := rawFragment(raw); frag != "" {
		in.Fragment = u.Fragment
		if strings.Contains(frag, "=") {
			in.FragParams = parsePairs(frag, true)
			if containsSecretish(in.FragParams) {
				in.Notes = append(in.Notes, Note{SevFail, "Credentials in the fragment",
					"This fragment carries what looks like a token. Fragments are not sent to servers, but they do land in browser history and in anything that logs a full URL."})
			}
		}
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
			fmt.Sprintf("Displays as %s, resolves as %s. Both forms are shown because they are the same host and only one of them is what you read.", in.HostUnicode, in.HostASCII)})
	}
	if label, scripts := mixedScriptLabel(in.HostUnicode); label != "" {
		in.Notes = append(in.Notes, Note{SevFail, "Mixed scripts in one label",
			fmt.Sprintf("The label %q mixes %s. Domains that mix writing systems within a single label are the standard shape of a homograph attack.", label, strings.Join(scripts, " and "))})
	}
	if ip := net.ParseIP(in.Host); ip != nil {
		in.Notes = append(in.Notes, Note{SevInfo, "Host is an IP address", "No DNS lookup is involved."})
	}
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
		p.Warn = "Contains '+', which is a space in a query string but a real character in base64. Both readings are shown because this value looks like base64 and only one of them preserves it."
	}
	if d, list := splitList(p.Value); d != "" {
		p.Delimiter, p.List = d, list
	}
	p.Layers = decodeLadder(p.Value)
	p.Kind = classify(p.Value)
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
	for _, p := range ps {
		if secretishKeys[strings.ToLower(p.Key)] && p.Value != "" {
			return true
		}
	}
	return false
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
