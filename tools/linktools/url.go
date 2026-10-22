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

// Service holds no state and opens no connections, so one value serves every request.
type Service struct{}

func NewService() *Service { return &Service{} }

// Inspector is never nil: Register panics on that wiring mistake rather than failing per request.
type Inspector interface {
	Parse(raw string) (*Inspection, error)
}

// maxInput bounds Parse, which is reachable unauthenticated; well above any real URL.
const maxInput = 64 << 10

// linkableSchemes is an allowlist of schemes rendered as anchors; Inspect shows possibly hostile URLs.
var linkableSchemes = map[string]bool{"http": true, "https": true}

// defaultPorts: ports that add nothing when written out.
var defaultPorts = map[string]string{"http": "80", "https": "443", "ftp": "21", "ws": "80", "wss": "443"}

// parseReason drops url.Error's `parse "<input>": ` prefix: the input is already on screen.
func parseReason(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if msg := err.Error(); strings.HasPrefix(msg, "net/url: ") {
		return errors.New(strings.TrimPrefix(msg, "net/url: "))
	}
	return err
}

// WrongTool's answers.
const (
	ToolCurl    = "curl"
	ToolExtract = "extract"
)

const (
	CurlNotURL = "That looks like a curl command, not a URL."
	TextNotURL = "That looks like text with links in it, not one URL."
)

// WrongTool names the page for input that is plainly not one URL, else "". It must never refuse a
// URL: markup needs a quoted href (links use ?href=), text needs words before or a link after.
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

// laterLink is a scheme:// after whitespace; templates/live.html carries the same expression.
var laterLink = regexp.MustCompile(`[ \t\r\n][A-Za-z][A-Za-z0-9+.-]*://`)

// Parse never fetches. Not url.ParseQuery: its map loses order, and it drops a pair with a bad escape.
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
	// A browser rewrites "%zz" to "%25zz" before following, so the link would go elsewhere.
	in.Linkable = linkableSchemes[strings.ToLower(u.Scheme)] && !hasBadEscape(raw)

	if u.Scheme == "" {
		in.Notes = append(in.Notes, Note{SevWarn, "No scheme",
			"Read as a relative path, so the first part is a folder name, not a host. Add https:// to the front to inspect it as a web address."})
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

	// WrongTool lets a lone URL with spaces through; this says what is wrong.
	if strings.ContainsAny(raw, " \t") {
		in.Notes = append(in.Notes, Note{SevWarn, "Unencoded spaces",
			"A URL cannot contain a raw space. A browser sends each one as %20, but in an email or a chat message the link usually stops at the first space. Replace them with %20 before sharing it."})
	}

	s.describeHost(in, u)
	s.describePath(in, u)

	in.Params = parsePairs(u.RawQuery, true)
	// A warning, not a failure: presigned URLs and magic links carry one on purpose.
	if keys := secretishNames(in.Params); len(keys) > 0 {
		in.Notes = append(in.Notes, Note{SevWarn, "Credentials in the query string",
			strings.Join(keys, ", ") + " looks like a token or a session. A query string reaches the server and its logs, stays in browser history, and can leak to other sites in the Referer header: share this URL as you would a password."})
	}
	if strings.Contains(u.RawQuery, ";") && !strings.Contains(u.RawQuery, "&") &&
		strings.Count(u.RawQuery, ";") >= 1 && len(in.Params) == 1 {
		in.Notes = append(in.Notes, Note{SevWarn, "Semicolon separators",
			"This query separates pairs with ';', which most modern servers no longer accept. It is shown as a single parameter because that is how a server would now read it."})
	}

	// Parsers that drop the fragment hide OAuth tokens; u.Fragment is decoded, so re-read the raw tail.
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

	if target, name, partial, ok := unwrapAll(raw); ok && !partial {
		in.Unwrapped, in.Wrapper = target, name
	}

	in.Canonical = canonicalise(u)
	return in, nil
}

// describeHost flags IDN homographs and userinfo used to disguise the real host.
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

// numericIPv4 reads a host as inet_aton and browsers do: "0x7f000001" and "127.1" are 127.0.0.1.
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

// describePath splits EscapedPath, not Path: Path has decoded %2F into a real slash.
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

// parsePairs is hand-rolled so order, repeats, valueless keys and broken escapes all survive.
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

// decodeOrRaw keeps the raw text on error: QueryUnescape returns "", making "?bad=%zz" look empty.
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

func enrichParam(p *Param, rawVal string) {
	// '+' is a space in a query but a real character in base64: show both readings, don't choose.
	if strings.Contains(rawVal, "+") && looksBase64(strings.ReplaceAll(rawVal, "%3D", "=")) {
		p.AltValue = rawVal
		p.Warn = "'+' means a space in a query but is a real character in base64. This value looks like base64, so both readings are shown."
	}
	if d, list := splitList(p.Value); d != "" {
		p.Delimiter, p.List = d, list
	}
	// Global rules only: a key alone can't tell ref=facebook from ref=main.
	p.Tracking = TrackingRuleFor(p.Key)
	p.Layers = decodeLadder(p.Value)
	p.Kind = classify(p.Value)
	p.Nested = nestedLink(p)
}

// nestedLink is the http(s) URL a parameter carries once decoded, or "".
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

// splitList returns the delimiter so the page can name it: "Smith,John" may well be one value.
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

// mixedScriptLabel uses the stdlib's range tables because idna exposes no script data.
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

// removeDotSegments is RFC 3986 §5.2.4 on the escaped path; path.Clean would drop the trailing slash.
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

// canonicalise applies lossless normalisations only; stripping parameters is Clean's lossy job.
func canonicalise(u *url.URL) string {
	c := *u
	c.Scheme = strings.ToLower(c.Scheme)
	// Never echo a password: String() writes userinfo verbatim. Keep the phishing-relevant username.
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
			// Hostname() strips IPv6 brackets, and "http://::1/" is not a URL.
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

// rawFragment: u.Fragment is already decoded, which would corrupt parameters inside it.
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

// secretishNames lists the credential-like keys in ps that carry a value.
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
