// Package linktools powers link.corpberry.com; only Trace and the short-link store open connections.
package linktools

import "errors"

// ErrDisabled means a dependency is switched off (no Mongo, key or tracer): a 503, never a 502.
var ErrDisabled = errors.New("feature is not enabled")

// Kind classifies a value for display and for the decode ladder; empty means an ordinary string.
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

// Severity vocabulary shared with the note partial, matching dnstools.
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

// Segment keeps a path segment's escaped form too: %2F inside a segment is not a separator.
type Segment struct {
	Index   int    `json:"index"`
	Raw     string `json:"raw"`
	Decoded string `json:"decoded"`
}

// Param is one key=value pair in order; a repeated key gets its own Param, never collapsed to last-wins.
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
	Nested    string   `json:"nested,omitempty"`    // the http(s) URL inside, once decoded
}

// Inspection is one parsed URL, fields in its left-to-right order. Parse opens no connection, but the URL
// still reaches logs and the CDN through the request path, hence platform.RedactURI.
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
	Absolute    string    `json:"absolute,omitempty"`        // no scheme: the same input with https:// in front
	Wrapper     string    `json:"wrapper,omitempty"`         // which wrapper was recognised
	Linkable    bool      `json:"linkable"`                  // scheme passed the allowlist
	Notes       []Note    `json:"notes,omitempty"`
}
