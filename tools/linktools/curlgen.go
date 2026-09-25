package linktools

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// Header is one HTTP request header. An ordered slice of these, rather than a
// map, for the same reason Param is a slice (types.go): a pasted command can
// repeat a header, and the order is part of what was pasted.
type Header struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// CurlOptions shapes the generated command (A19,
// docs/01-feature-inventory.md).
type CurlOptions struct {
	Persona         string `json:"persona"`          // a trace.go persona key; empty sends curl's own UA
	Method          string `json:"method"`           // empty or GET emits no -X
	FollowRedirects bool   `json:"follow_redirects"` // -L
	ShowHeaders     bool   `json:"show_headers"`     // -i
	Insecure        bool   `json:"insecure"`         // -k; see the note on ToCurl
}

// curlPersona resolves a persona key against the one table this package keeps,
// trace.go's personas (A17). Deliberately not a second table: the whole value of
// the feature is that the curl line and the traced request claim to be the same
// agent, and two lists would drift the day one of them gained an entry.
//
// Unlike trace.go's personaFor, an unrecognised key is an error rather than a
// fallback to the default. A trace with the wrong user agent still reports which
// one answered; a generated command hands the caller a line that silently claims
// to be somebody else.
func curlPersona(key string) (Persona, bool) {
	for _, p := range personas {
		if strings.EqualFold(p.Key, key) {
			return p, true
		}
	}
	return Persona{}, false
}

// ToCurl renders a runnable curl command for one URL.
//
// Everything the caller supplied is single-quoted, and an embedded single quote
// is written '\” — close the quote, emit an escaped one, reopen. This is not
// decoration. A URL is attacker-influenced text and the output is something a
// human pastes into a shell, so an unquoted "&", ";", "|" or "$(…)" inside one
// would stop being part of the URL and start being shell syntax on their
// machine. Nothing here is ever emitted bare, and the URL is parsed before it is
// quoted so a control character cannot reach the clipboard at all.
//
// opt.Insecure emits -k, which turns off certificate verification and turns the
// request into one anybody on the path can read and rewrite. It is emitted only
// when explicitly asked for, never as part of a default, and it is worth
// treating a habit of reaching for it as a bug in the server being tested.
func (s *Service) ToCurl(raw string, opt CurlOptions) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("no URL given")
	}
	if len(raw) > maxInput {
		return "", fmt.Errorf("URL is %d bytes; the limit is %d", len(raw), maxInput)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("not a URL: %w", err)
	}
	if isDangerousScheme(u.Scheme) {
		// Checked before the host, because "javascript:alert(1)" has no host
		// either and "it needs a host" is the wrong thing to tell someone about
		// it. Shares url.go's table: these are the schemes a browser executes or
		// resolves locally rather than fetches over the wire.
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
	// No flag for the other direction: curl does not follow a redirect unless
	// asked, so "--max-redirs 0" without -L is a no-op, and a no-op flag on a
	// line a human will paste is just noise.
	if opt.ShowHeaders {
		args = append(args, "-i")
	}
	if opt.Insecure {
		args = append(args, "-k")
	}
	if opt.Persona != "" {
		p, ok := curlPersona(opt.Persona)
		if !ok {
			// Not silently ignored: a typo that quietly sends the wrong user
			// agent defeats the only reason the option exists.
			return "", fmt.Errorf("unknown persona %q", opt.Persona)
		}
		args = append(args, "-H", shellQuote("User-Agent: "+p.UA))
	}
	args = append(args, shellQuote(raw))
	return strings.Join(args, " "), nil
}

// FromCurl takes a pasted curl command apart and returns its URL and headers.
//
// The genuinely useful half of A19. People paste curl lines out of documentation
// and out of a browser's "Copy as cURL" constantly — the browser's version is
// multi-line, continuation-escaped and carries twenty -H flags — and nothing in
// the surveyed landscape takes one apart.
//
// This is a shell-shaped tokeniser, not a shell. It understands the quoting
// forms that actually appear in a copied command and nothing else: no variable
// expansion, no command substitution, no globbing, no execution. The input is
// untrusted text and the only safe way to read it is to not evaluate it.
//
// The URL is returned exactly as it was written, including a missing scheme.
// curl would assume http there; Parse says so in a note instead, and inventing
// the scheme here would hide the fact that the pasted command relied on it.
func (s *Service) FromCurl(cmd string) (string, []Header, error) {
	if strings.TrimSpace(cmd) == "" {
		return "", nil, fmt.Errorf("no command given")
	}
	if len(cmd) > maxInput {
		return "", nil, fmt.Errorf("command is %d bytes; the limit is %d", len(cmd), maxInput)
	}

	toks := shellSplit(cmd)
	i := 0
	for i < len(toks) && isPromptNoise(toks[i]) {
		i++
	}
	if i < len(toks) && isCurlWord(toks[i]) {
		i++
	}

	var target string
	var headers []Header
	for i < len(toks) {
		t := toks[i]
		i++
		if t == "--" {
			// End of flags: whatever follows is an operand, even if it starts
			// with a dash.
			for ; i < len(toks); i++ {
				if target == "" && looksLikeURL(toks[i]) {
					target = toks[i]
				}
			}
			break
		}
		if !strings.HasPrefix(t, "-") || t == "-" {
			// curl accepts several URLs; this tool inspects one, so the first
			// wins and the rest are left alone.
			if target == "" && looksLikeURL(t) {
				target = t
			}
			continue
		}

		name, val, hasVal := splitCurlFlag(t)
		if !hasVal && curlFlagTakesArg(name) && i < len(toks) {
			// Consuming the argument matters even for flags we ignore: without
			// it, the filename after -o or the body after -d becomes the URL.
			val, hasVal = toks[i], true
			i++
		}
		if !hasVal {
			continue
		}
		switch name {
		case "-H", "--header":
			if h, ok := parseHeaderArg(val); ok {
				headers = append(headers, h)
			}
		case "--url":
			if target == "" {
				target = val
			}
		case "-A", "--user-agent":
			headers = append(headers, Header{"User-Agent", val})
		case "-e", "--referer":
			headers = append(headers, Header{"Referer", strings.TrimSuffix(val, ";auto")})
		case "-b", "--cookie":
			// curl reads this as a file when it has no "=" in it, and a file
			// name is not a header.
			if strings.Contains(val, "=") {
				headers = append(headers, Header{"Cookie", val})
			}
		}
	}

	if target == "" {
		return "", nil, fmt.Errorf("no URL in that command")
	}
	if _, err := url.Parse(target); err != nil {
		return "", nil, fmt.Errorf("the command's URL is not a URL: %w", err)
	}
	return target, headers, nil
}

// shellQuote wraps s in single quotes for POSIX sh.
//
// Single quotes are the only quoting form in which nothing at all is special,
// which is why this uses them and not double quotes: inside '…' a "$", a
// backtick and a backslash are literal bytes. The one character that cannot
// appear is a single quote, written as '\” — end the quoted run, emit an
// escaped quote outside it, start a new run. Every caller-supplied piece of the
// command goes through here; see the note on ToCurl for why.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// shellSplit breaks a pasted command into tokens, honouring the quoting the
// browsers and the documentation actually emit: '…', "…" with backslash
// escapes, $'…' ANSI-C quoting, bare backslash escapes, and line continuations
// in all three flavours a "Copy as cURL" produces.
func shellSplit(s string) []string {
	var out []string
	var cur strings.Builder
	open := false // a token is in progress, even when it is the empty ''

	push := func() {
		if open {
			out = append(out, cur.String())
			cur.Reset()
			open = false
		}
	}

	for i := 0; i < len(s); {
		c := s[i]
		switch {
		case (c == '\\' || c == '^' || c == '`') && i+1 < len(s) && (s[i+1] == '\n' || s[i+1] == '\r'):
			// Line continuation. bash writes "\", cmd.exe writes "^",
			// PowerShell writes "`", and Chrome's copy menu offers all three.
			i += 2
		case c == '\\' && i+1 < len(s):
			cur.WriteByte(s[i+1])
			open = true
			i += 2
		case c == '$' && i+1 < len(s) && s[i+1] == '\'':
			// $'…': bash reaches for this as soon as a header value contains a
			// quote or a non-ASCII byte, so a copied command hits it often.
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
			cur.WriteString(ansiCDecode(raw.String()))
			open = true
			i = j + 1
		case c == '\'':
			j := i + 1
			for j < len(s) && s[j] != '\'' {
				cur.WriteByte(s[j]) // nothing is special inside single quotes
				j++
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
				cur.WriteByte(s[j])
				j++
			}
			open = true
			i = j + 1
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			push()
			i++
		default:
			cur.WriteByte(c)
			open = true
			i++
		}
	}
	push()
	return out
}

// ansiCDecode expands the escapes inside bash's $'…' quoting. An escape it does
// not know keeps its backslash, which is what bash does with it too.
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

// curlArgFlags: the long flags whose next token is a value rather than a URL.
// The list does not have to be exhaustive for the parser to work, but every
// entry missing from it is a chance to mistake a filename or a POST body for the
// URL, so the ones that show up in a copied command are all here.
var curlArgFlags = map[string]bool{
	"--header": true, "--url": true, "--request": true, "--data": true,
	"--data-raw": true, "--data-binary": true, "--data-urlencode": true,
	"--data-ascii": true, "--form": true, "--form-string": true, "--user": true,
	"--user-agent": true, "--referer": true, "--cookie": true, "--cookie-jar": true,
	"--output": true, "--dump-header": true, "--proxy": true, "--proxy-user": true,
	"--cert": true, "--key": true, "--cacert": true, "--capath": true,
	"--range": true, "--retry": true, "--max-time": true, "--max-redirs": true,
	"--connect-timeout": true, "--resolve": true, "--write-out": true,
	"--upload-file": true, "--oauth2-bearer": true, "--aws-sigv4": true,
	"--interface": true, "--limit-rate": true, "--time-cond": true,
	"--continue-at": true, "--config": true, "--netrc-file": true,
}

// curlArgShorts: the single-letter flags that take a value. Kept as a string
// because splitCurlFlag walks a cluster like "-sSLXPOST" byte by byte.
const curlArgShorts = "AbCcDdEeFHKmoPQrTtUuwXxYyz"

func curlFlagTakesArg(name string) bool {
	if strings.HasPrefix(name, "--") {
		return curlArgFlags[name]
	}
	return len(name) == 2 && strings.IndexByte(curlArgShorts, name[1]) >= 0
}

// splitCurlFlag normalises one flag token into a name and, when the value was
// attached rather than separate, that value.
//
// "-sSL" is three booleans, "-XPOST" is a flag with its value stuck to it, and
// "-sSLXPOST" is both — so a short cluster is walked until a letter that takes
// an argument, and everything after that letter is the argument.
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

// parseHeaderArg reads one -H argument. Returns false for the shapes curl treats
// as something other than a header to send.
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

// isPromptNoise skips what comes along when a command is copied out of a
// terminal or a README rather than out of a browser.
func isPromptNoise(t string) bool {
	switch t {
	case "$", "%", "#", ">", "PS>", "sudo", "&&", ";", "|":
		return true
	}
	return false
}

// looksLikeURL keeps a stray word from being read as the URL. It matters because
// a pasted line is not always curl's: "wget https://…", "http GET https://…" and
// "xh https://…" all arrive here, and without this the program name becomes the
// answer. Deliberately loose — a host with no dot and no scheme is real on a LAN,
// hence the localhost and bracketed-IPv6 cases.
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

// isMethodToken keeps an edited method to RFC 9110's token shape. The command is
// quoted anyway, so this is not what stops an injection; it stops a newline or a
// stray flag from being pasted into somebody's shell looking like part of curl.
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
