// Package linktools powers link.corpberry.com: a suite of URL tools sharing one
// parser. Parsing, cleaning, unwrapping and rebuilding are pure and open no
// connections; only Trace and the short-link store reach outside the process.
//
// Layering follows docs/ARCHITECTURE.md §4 — everything in this file and its
// neighbours returns structs and knows nothing about HTTP. handler.go is the
// only file that imports echo.
package linktools

import "errors"

// ErrDisabled: a dependency this route needs is switched off (no Mongo, no API
// key, no tracer). Handlers turn it into 503, never 502: nothing failed, the
// feature simply is not running. Mirrors iptools.ErrUnavailable.
var ErrDisabled = errors.New("feature is not enabled")

// Kind classifies a parameter value so the template can render it usefully and
// so the decode ladder knows whether to descend. Empty means "ordinary string".
type Kind string

const (
	KindNumber    Kind = "number"
	KindBool      Kind = "bool"
	KindURL       Kind = "url"
	KindJSON      Kind = "json"
	KindJWT       Kind = "jwt"
	KindBase64    Kind = "base64"
	KindUUID      Kind = "uuid"
	KindTimestamp Kind = "timestamp"
	KindHex       Kind = "hex"
	KindEmail     Kind = "email"
)

// Severity vocabulary shared with the note partial, matching dnstools so the
// templates and the aria labels read the same across tools.
const (
	SevFail = "fail"
	SevWarn = "warn"
	SevOK   = "ok"
	SevInfo = "info"
)

// Note is a severity-tagged observation about a URL as a whole.
type Note struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
}

// Layer is one rung of the decode ladder: what was applied, and what came out.
type Layer struct {
	Depth  int    `json:"depth"`
	Method string `json:"method"` // "percent", "base64", "base64url", "json", "jwt-payload"
	Value  string `json:"value"`
}

// Segment is one decoded path segment, kept alongside its escaped form because
// %2F inside a segment is not a separator and collapsing the two changes the
// meaning of the path.
type Segment struct {
	Index   int    `json:"index"`
	Raw     string `json:"raw"`
	Decoded string `json:"decoded"`
}

// Param is one key=value pair, in the order it appeared.
//
// Repeated keys produce one Param each. Every hosted parser surveyed either
// collapses them to last-wins or hides them in a map, and both lose a real class
// of bug — see docs/reports/jsonutilities-query-string-parser.md.
type Param struct {
	Index     int      `json:"index"`
	Key       string   `json:"key"`
	RawKey    string   `json:"raw_key,omitempty"` // only when decoding changed it
	Value     string   `json:"value"`
	RawValue  string   `json:"raw_value,omitempty"` // only when decoding changed it
	Repeat    bool     `json:"repeat,omitempty"`    // 2nd+ occurrence of this key
	Valueless bool     `json:"valueless,omitempty"` // "?debug", no "=" at all
	Kind      Kind     `json:"kind,omitempty"`
	List      []string `json:"list,omitempty"`      // split when the value is delimited
	Delimiter string   `json:"delimiter,omitempty"` // named, never applied silently
	Layers    []Layer  `json:"layers,omitempty"`    // the ladder, when it went deeper
	Tracking  string   `json:"tracking,omitempty"`  // rule name, when Clean would strip this
	AltValue  string   `json:"alt_value,omitempty"` // the other reading of an ambiguous "+"
	Warn      string   `json:"warn,omitempty"`      // bad escape, ambiguous "+", non-UTF8
}

// Inspection is one parsed URL. Field order mirrors the URL's own left-to-right
// shape so a template can walk it without reordering.
//
// Parse opens no connection. The URL does still reach Mongo, stdout, nginx and
// Cloudflare through the ordinary request path, which is why platform.RedactURI
// exists — see docs/06-security-and-abuse.md §5. "We don't fetch it" is the
// honest claim; "it never leaves the box" is not.
type Inspection struct {
	Input       string    `json:"input"`
	Canonical   string    `json:"canonical,omitempty"`
	Scheme      string    `json:"scheme"`
	Opaque      string    `json:"opaque,omitempty"` // non-hierarchical, e.g. javascript:, mailto:
	User        string    `json:"user,omitempty"`
	HasPass     bool      `json:"has_password,omitempty"` // value never echoed
	Host        string    `json:"host"`
	HostASCII   string    `json:"host_ascii,omitempty"`
	HostUnicode string    `json:"host_unicode,omitempty"`
	Port        string    `json:"port,omitempty"`
	DefaultPort bool      `json:"default_port,omitempty"`
	Path        string    `json:"path,omitempty"`
	Segments    []Segment `json:"segments,omitempty"`
	Params      []Param   `json:"params,omitempty"`
	Fragment    string    `json:"fragment,omitempty"`
	FragParams  []Param   `json:"fragment_params,omitempty"` // OAuth implicit flow lives here
	Unwrapped   string    `json:"unwrapped,omitempty"`       // A16: real target behind a wrapper
	Wrapper     string    `json:"wrapper,omitempty"`         // which wrapper was recognised
	Linkable    bool      `json:"linkable"`                  // scheme passed the allowlist
	Notes       []Note    `json:"notes,omitempty"`
}
