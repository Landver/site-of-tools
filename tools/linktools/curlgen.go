package linktools

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Header is one request header, kept in an ordered slice because a pasted command can repeat one.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CurlOptions shapes the generated command (A19, docs/01-feature-inventory.md).
type CurlOptions struct {
	Persona         string `json:"persona"`          // a trace.go persona key; empty sends curl's own UA
	Method          string `json:"method"`           // empty or GET emits no -X
	FollowRedirects bool   `json:"follow_redirects"` // -L
	ShowHeaders     bool   `json:"show_headers"`     // -i
	Insecure        bool   `json:"insecure"`         // -k; see the note on ToCurl
}

// ToCurl renders a runnable curl command. Every caller-supplied piece is single-quoted, since the URL is
// attacker-influenced and gets pasted into a shell. -k is emitted only when opt.Insecure asks for it.
func (s *Service) ToCurl(raw string, opt CurlOptions) (string, error) {
	raw, err := readURL(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a valid URL: %w", parseReason(err))
	}
	if isDangerousScheme(u.Scheme) {
		// Before the host check: javascript:alert(1) has no host either, and "needs a host" is wrong there.
		return "", fmt.Errorf("curl fetches over the network and %q is not a network scheme", u.Scheme+":")
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("curl needs an absolute URL with a host, and %q has none", raw)
	}

	args := []string{"curl"}
	if m := strings.ToUpper(strings.TrimSpace(opt.Method)); m != "" && m != "GET" {
		if !isMethodToken(m) {
			return "", fmt.Errorf("%q is not an HTTP method", opt.Method)
		}
		args = append(args, "-X", shellQuote(m))
	}
	if opt.FollowRedirects {
		args = append(args, "-L")
	}
	// No flag for the other direction: curl only follows redirects when asked, so --max-redirs 0 is noise.
	if opt.ShowHeaders {
		args = append(args, "-i")
	}
	if opt.Insecure {
		args = append(args, "-k")
	}
	if opt.Persona != "" {
		p, ok := lookupPersona(opt.Persona)
		if !ok {
			// A typo quietly sending the wrong user agent would defeat the option.
			return "", fmt.Errorf("unknown persona %q", opt.Persona)
		}
		args = append(args, "-H", shellQuote("User-Agent: "+p.UA))
	}
	// curl globs [] and {} in a URL ("ids[]=1" fails, exit 3) unless told not to.
	if strings.ContainsAny(raw, "[]{}") {
		args = append(args, "-g")
	}
	args = append(args, shellQuote(raw))
	return strings.Join(args, " "), nil
}

// CurlRequest is a pasted command taken apart; the body is measured, never echoed: it holds passwords.
type CurlRequest struct {
	URL       string   `json:"url"`
	Headers   []Header `json:"headers"`
	Method    string   `json:"method"`
	MethodWhy string   `json:"method_why"`
	BodyBytes int      `json:"body_bytes,omitempty"`
	Notes     []Note   `json:"notes,omitempty"`
	bodyFlag  string   // the first flag that carried a body, which MethodWhy names
}

// CurlParse is a pasted command taken apart, with its URL inspected as Parse does.
type CurlParse struct {
	CurlRequest
	Inspection *Inspection `json:"inspection"`
}

// ParseCurl reads a pasted curl command without evaluating it: a shell-shaped tokeniser, not a shell.
// The URL comes back as written; a missing scheme is left for Parse to note rather than invented here.
func (s *Service) ParseCurl(cmd string) (*CurlParse, error) {
	r, err := readCurl(strings.TrimSpace(cmd))
	if err != nil {
		return nil, err
	}
	in, err := s.inspect(r.URL)
	if err != nil {
		return nil, err
	}
	return &CurlParse{CurlRequest: *r, Inspection: in}, nil
}

// urlencodeData encodes a --data-urlencode argument as curl does; "@file" is left alone.
func urlencodeData(v string) string {
	esc := func(x string) string { return strings.ReplaceAll(url.QueryEscape(x), "+", "%20") }
	if strings.HasPrefix(v, "@") || strings.Contains(v, "@") && !strings.Contains(v, "=") {
		return v
	}
	if name, content, ok := strings.Cut(v, "="); ok {
		if name == "" {
			return esc(content)
		}
		return name + "=" + esc(content)
	}
	return esc(v)
}

// readCurl tokenises cmd and accounts for its URL, headers, method and body.
func readCurl(cmd string) (*CurlRequest, error) {
	if cmd == "" {
		return nil, fmt.Errorf("no command given")
	}
	if len(cmd) > maxInput {
		return nil, fmt.Errorf("command is %d bytes, over the %d KB limit", len(cmd), maxInput>>10)
	}

	toks, info := shellSplit(cmd)
	if info.unterminated {
		// A shell would wait for more input; any parse would be a guess.
		return nil, fmt.Errorf("the command has a quote that is never closed")
	}
	r := &CurlRequest{}
	i := 0
	for i < len(toks) && isPromptNoise(toks[i]) {
		i++
	}
	if i < len(toks) && isCurlWord(toks[i]) {
		i++
	} else if i == len(toks)-1 && looksLikeURL(toks[i]) {
		r.Notes = append(r.Notes, Note{SevInfo, "Only a URL",
			"There is no command here, just a URL, so it was read as a bare curl call. To turn it into a command, use Build a command."})
	} else if i < len(toks) && !looksLikeURL(toks[i]) && !strings.HasPrefix(toks[i], "-") {
		r.Notes = append(r.Notes, Note{SevWarn, "Not a curl command",
			"It starts with " + toks[i] + ", and was read as if it were curl. Flags can mean something else to another program."})
	}
	if info.stoppedAt != "" {
		r.Notes = append(r.Notes, Note{SevWarn, "The command ends at an unquoted " + info.stoppedAt,
			"A shell would stop curl's arguments there and treat the rest as another command, so only the part before it is read. If it belongs to a URL, the URL needs quotes."})
	}
	if info.expansion {
		r.Notes = append(r.Notes, Note{SevInfo, "Shell expansion left as written",
			"The command contains $… or backticks outside single quotes. A shell would replace them before curl runs; they are shown literally here, and nothing is ever executed."})
	}
	var explicit string // -X
	var get, head bool  // -G, -I
	var data []string   // body arguments, for -G, which moves them into the query
	for i < len(toks) {
		t := toks[i]
		i++
		if t == "--" {
			// End of flags: whatever follows is an operand, even if it starts with a dash.
			for ; i < len(toks); i++ {
				if r.URL == "" && looksLikeURL(toks[i]) {
					r.URL = toks[i]
				}
			}
			break
		}
		if !strings.HasPrefix(t, "-") || t == "-" {
			// curl accepts several URLs; this tool inspects the first.
			if r.URL == "" && looksLikeURL(t) {
				r.URL = t
			}
			continue
		}

		name, val, hasVal := splitCurlFlag(t)
		switch {
		case name == "--get":
			get = true
		case name == "--head":
			head = true
		case !strings.HasPrefix(t, "--"):
			// "-sSLG", "-GXPOST": G and I count only before the first letter that takes an argument.
			bools := t[1:]
			if j := strings.IndexAny(bools, curlArgShorts); j >= 0 {
				bools = bools[:j]
			}
			get = get || strings.ContainsRune(bools, 'G')
			head = head || strings.ContainsRune(bools, 'I')
		}
		if !hasVal && curlFlagTakesArg(name) && i < len(toks) {
			// Consume it even for flags we ignore, or the file after -o or body after -d becomes the URL.
			val, hasVal = toks[i], true
			i++
		}
		if !hasVal {
			continue
		}
		switch name {
		case "-H", "--header":
			if h, ok := parseHeaderArg(val); ok {
				r.Headers = append(r.Headers, h)
			}
		case "--url":
			if r.URL == "" {
				r.URL = val
			}
		case "-A", "--user-agent":
			r.Headers = append(r.Headers, Header{"User-Agent", val})
		case "-e", "--referer":
			r.Headers = append(r.Headers, Header{"Referer", strings.TrimSuffix(val, ";auto")})
		case "-b", "--cookie":
			// Without "=" curl reads this as a file name, which is not a header.
			if strings.Contains(val, "=") {
				r.Headers = append(r.Headers, Header{"Cookie", val})
			}
		case "-X", "--request":
			explicit = strings.ToUpper(val)
		case "-d", "--data", "--data-raw", "--data-binary", "--data-ascii", "--data-urlencode", "-F", "--form", "--form-string", "--json":
			if r.bodyFlag == "" {
				r.bodyFlag = name
			}
			r.BodyBytes += len(val)
			if name == "--data-urlencode" {
				val = urlencodeData(val)
			}
			data = append(data, val)
		case "-u", "--user":
			// Shown as the header curl would build, never with the password.
			user, _, _ := strings.Cut(val, ":")
			r.Headers = append(r.Headers, Header{"Authorization", "Basic, from -u (user " + user + ", password not shown)"})
		}
	}

	if r.URL == "" {
		return nil, fmt.Errorf("no URL in that command")
	}
	if _, err := url.Parse(r.URL); err != nil {
		return nil, fmt.Errorf("couldn't read the URL in that command: %w", parseReason(err))
	}

	// curl's precedence: -X, then -I, then -G (body into the query string), then a body means POST.
	switch {
	case explicit != "":
		r.Method, r.MethodWhy = explicit, "set with -X"
	case head:
		r.Method, r.MethodWhy = "HEAD", "implied by -I"
	case get && r.bodyFlag != "":
		r.Method, r.MethodWhy = "GET", "-G moves the "+r.bodyFlag+" data into the query string"
		sep := "?"
		if strings.Contains(r.URL, "?") {
			sep = "&"
		}
		r.URL += sep + strings.ReplaceAll(strings.Join(data, "&"), " ", "%20")
		r.BodyBytes = 0
	case r.bodyFlag != "":
		r.Method, r.MethodWhy = "POST", "implied by "+r.bodyFlag
	default:
		r.Method, r.MethodWhy = "GET", "curl's default"
	}
	return r, nil
}

// shellQuote single-quotes s for POSIX sh, where nothing inside is special; an embedded single quote
// closes the run, is escaped, and reopens it.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellSplit honours the quoting copied commands use: '…', "…", $'…', backslashes and line continuations.
func shellSplit(s string) ([]string, shellInfo) {
	var out []string
	var info shellInfo
	var cur strings.Builder
	open := false // a token is in progress, even when it is the empty ''

	push := func() {
		if open {
			out = append(out, cur.String())
			cur.Reset()
			open = false
		}
	}
	// A shell substitutes these before curl runs, so the text is not what curl gets.
	expansion := func(i int) {
		if i+1 < len(s) {
			n := s[i+1]
			if n == '(' || n == '{' || n == '_' || n >= 'A' && n <= 'Z' || n >= 'a' && n <= 'z' {
				info.expansion = true
			}
		}
	}

	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case (c == '\\' || c == '^' || c == '`') && i+1 < len(s) && (s[i+1] == '\n' || s[i+1] == '\r'):
			// Line continuation: bash "\", cmd.exe "^", PowerShell "`"; Chrome's copy menu offers all three.
			i += 2
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			open = true
			i += 2
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			// $'…': bash emits it once a header value has a quote or non-ASCII byte, so copies hit it often.
			var raw strings.Builder
			j := i + 2
			for j < len(s) && s[j] != '\'' {
				if s[j] == '\\' && j+1 < len(s) {
					raw.WriteByte(s[j])
					raw.WriteByte(s[j+1])
					j += 2
					continue
				}
				raw.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				info.unterminated = true
			}
			cur.WriteString(ansiCDecode(raw.String()))
			open = true
			i = j + 1
		case c == '\'':
			j := i + 1
			for j < len(s) && s[j] != '\'' {
				cur.WriteByte(s[j]) // nothing is special inside single quotes
				j++
			}
			if j >= len(s) {
				info.unterminated = true
			}
			open = true
			i = j + 1
		case c == '"':
			j := i + 1
			for j < len(s) && s[j] != '"' {
				if s[j] == '\\' && j+1 < len(s) {
					switch s[j+1] {
					case '"', '\\', '$', '`':
						cur.WriteByte(s[j+1])
						j += 2
						continue
					case '\n':
						j += 2
						continue
					}
				}
				if s[j] == '$' {
					expansion(j)
				}
				if s[j] == '`' {
					info.expansion = true
				}
				cur.WriteByte(s[j])
				j++
			}
			if j >= len(s) {
				info.unterminated = true
			}
			open = true
			i = j + 1
		case c == ';' || c == '&' || c == '|':
			// A shell ends the command here; curl never sees the rest.
			push()
			info.stoppedAt = string(c)
			if i+1 < len(s) && (s[i+1] == '&' || s[i+1] == '|') {
				info.stoppedAt += string(s[i+1])
			}
			return out, info
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			push()
			i++
		default:
			if c == '$' {
				expansion(i)
			}
			if c == '`' {
				info.expansion = true
			}
			cur.WriteByte(c)
			open = true
			i++
		}
	}
	push()
	return out, info
}

// shellInfo is the shell syntax shellSplit noticed but does not run.
type shellInfo struct {
	unterminated bool
	stoppedAt    string // the operator the command ended at: ";", "&&", "|", …
	expansion    bool
}

// ansiCDecode expands escapes inside bash's $'…'; an unknown escape keeps its backslash, as in bash.
func ansiCDecode(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\\' || i+1 >= len(s) {
			b.WriteByte(s[i])
			i++
			continue
		}
		i++
		switch c := s[i]; c {
		case 'n':
			b.WriteByte('\n')
			i++
		case 't':
			b.WriteByte('\t')
			i++
		case 'r':
			b.WriteByte('\r')
			i++
		case 'a':
			b.WriteByte(7)
			i++
		case 'b':
			b.WriteByte(8)
			i++
		case 'f':
			b.WriteByte(12)
			i++
		case 'v':
			b.WriteByte(11)
			i++
		case 'e', 'E':
			b.WriteByte(27)
			i++
		case '\\', '\'', '"', '?':
			b.WriteByte(c)
			i++
		case 'x', 'u', 'U':
			width := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
			i++
			j := i
			for j < len(s) && j < i+width && isHexDigit(s[j]) {
				j++
			}
			if j == i {
				b.WriteByte('\\')
				b.WriteByte(c)
				continue
			}
			n, _ := strconv.ParseUint(s[i:j], 16, 32)
			if c == 'x' {
				b.WriteByte(byte(n))
			} else {
				b.WriteRune(rune(n))
			}
			i = j
		default:
			if c >= '0' && c <= '7' {
				j := i
				for j < len(s) && j < i+3 && s[j] >= '0' && s[j] <= '7' {
					j++
				}
				n, _ := strconv.ParseUint(s[i:j], 8, 32)
				b.WriteByte(byte(n))
				i = j
				continue
			}
			b.WriteByte('\\')
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// curlArgFlags lists long flags taking a value; any missing one lets a file name or body pose as the URL.
var curlArgFlags = map[string]bool{
	"--header": true, "--url": true, "--request": true, "--data": true,
	"--data-raw": true, "--data-binary": true, "--data-urlencode": true,
	"--data-ascii": true, "--form": true, "--form-string": true, "--json": true, "--user": true,
	"--user-agent": true, "--referer": true, "--cookie": true, "--cookie-jar": true,
	"--output": true, "--dump-header": true, "--proxy": true, "--proxy-user": true,
	"--cert": true, "--key": true, "--cacert": true, "--capath": true,
	"--range": true, "--retry": true, "--max-time": true, "--max-redirs": true,
	"--connect-timeout": true, "--resolve": true, "--write-out": true,
	"--upload-file": true, "--oauth2-bearer": true, "--aws-sigv4": true,
	"--interface": true, "--limit-rate": true, "--time-cond": true,
	"--continue-at": true, "--config": true, "--netrc-file": true,
}

// curlArgShorts is a string because splitCurlFlag walks a cluster like "-sSLXPOST" byte by byte.
const curlArgShorts = "AbCcDdEeFHKmoPQrTtUuwXxYyz"

func curlFlagTakesArg(name string) bool {
	if strings.HasPrefix(name, "--") {
		return curlArgFlags[name]
	}
	return len(name) == 2 && strings.IndexByte(curlArgShorts, name[1]) >= 0
}

// splitCurlFlag walks a cluster like "-sSLXPOST" to the first letter taking a value; the rest is that value.
func splitCurlFlag(t string) (name, val string, hasVal bool) {
	if strings.HasPrefix(t, "--") {
		if n, v, ok := strings.Cut(t, "="); ok {
			return n, v, true
		}
		return t, "", false
	}
	for i := 1; i < len(t); i++ {
		if strings.IndexByte(curlArgShorts, t[i]) >= 0 {
			return "-" + string(t[i]), t[i+1:], i+1 < len(t)
		}
	}
	return t, "", false
}

// parseHeaderArg reads one -H argument, rejecting shapes curl treats as something other than a header.
func parseHeaderArg(s string) (Header, bool) {
	name, value, ok := strings.Cut(s, ":")
	if !ok {
		// "-H 'X-Foo;'" is curl's spelling for "send X-Foo with no value".
		if n := strings.TrimSpace(strings.TrimSuffix(s, ";")); n != s && n != "" {
			return Header{Name: n}, true
		}
		return Header{}, false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return Header{}, false
	}
	return Header{Name: name, Value: strings.TrimSpace(value)}, true
}

// isPromptNoise skips what comes along when a command is copied from a terminal or a README.
func isPromptNoise(t string) bool {
	switch t {
	case "$", "%", "#", ">", "PS>", "sudo", "&&", ";", "|":
		return true
	}
	return false
}

// looksLikeURL stops a program name (wget, xh, http) becoming the URL; loose, as LAN hosts lack dots.
func looksLikeURL(t string) bool {
	if strings.Contains(t, "://") || strings.HasPrefix(t, "[") {
		return true
	}
	if strings.HasPrefix(t, "localhost") || strings.Contains(t, ":") && strings.Contains(t, "/") {
		return true
	}
	return strings.Contains(t, ".") && !strings.HasPrefix(t, ".")
}

func isCurlWord(t string) bool {
	t = strings.ToLower(strings.TrimSuffix(t, ".exe"))
	return t == "curl" || strings.HasSuffix(t, "/curl")
}

// isMethodToken enforces RFC 9110's token shape: quoting stops injection, this stops a stray newline.
func isMethodToken(m string) bool {
	if m == "" {
		return false
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}
