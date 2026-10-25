package mailtools

import (
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

const (
	maxBIMIFileSize = 32 * 1024
	svgNS           = "http://www.w3.org/2000/svg"
)

// BIMIFinding is the outcome of one BIMI rule.
type BIMIFinding struct {
	Severity string `json:"severity"` // "ok", "fail"
	Rule     string `json:"rule"`
	Detail   string `json:"detail"`
	Fixable  bool   `json:"fixable"`
}

// BIMIValidation holds the validation audit result for an SVG logo.
type BIMIValidation struct {
	Compliant    bool          `json:"compliant"`
	FileSize     int           `json:"file_size"`
	Version      string        `json:"version,omitempty"`
	BaseProfile  string        `json:"base_profile,omitempty"`
	ViewBox      string        `json:"viewbox,omitempty"`
	AspectRatio  string        `json:"aspect_ratio,omitempty"`
	SquareAspect bool          `json:"square_aspect"`
	Findings     []BIMIFinding `json:"findings"`
	FailCount    int           `json:"fail_count"`
	AutoFixedSVG string        `json:"auto_fixed_svg,omitempty"` // set when a fixable rule failed
	// PreviewBase64 feeds an <img> data: URI, where the logo's scripts never run.
	PreviewBase64 string `json:"-"`
}

// SVG Tiny P/S forbids scripting and embedded content.
var bimiForbidden = []string{"script", "foreignObject", "iframe", "canvas", "audio", "video", "object", "embed"}

var (
	reNetworkURL = regexp.MustCompile(`(?i)^\s*(https?:)?//`)
	reCSSFetch   = regexp.MustCompile(`(?i)@import|url\s*\(\s*["']?\s*(https?:)?//`)
)

// ValidateBIMI audits raw SVG text against the strict BIMI SVG Tiny P/S profile.
func ValidateBIMI(rawSVG string) (*BIMIValidation, error) {
	doc, err := parseSVG(rawSVG)
	if err != nil {
		return nil, err
	}
	v := &BIMIValidation{
		FileSize:      len(doc.src),
		Version:       doc.attr("version"),
		BaseProfile:   doc.attr("baseProfile"),
		ViewBox:       doc.attr("viewBox"),
		PreviewBase64: base64.StdEncoding.EncodeToString([]byte(doc.src)),
	}
	if box, ok := parseViewBox(v.ViewBox); ok {
		v.AspectRatio = fmt.Sprintf("%g:%g", box[2], box[3])
		v.SquareAspect = box[2] == box[3]
	}

	forbidden := "SVG Tiny P/S forbids scripts, <foreignObject> and embedded media."
	if len(doc.forbidden) > 0 {
		forbidden = fmt.Sprintf("Found <%s>. %s", strings.Join(doc.forbidden, ">, <"), forbidden)
	}

	v.check("File Size Limit (<= 32 KB)", v.FileSize <= maxBIMIFileSize, false,
		fmt.Sprintf("SVG is %d bytes; BIMI allows at most 32,768.", v.FileSize))
	v.check("SVG Namespace", doc.attr("xmlns") == svgNS, true,
		fmt.Sprintf("Root declares xmlns=%q; BIMI requires %q.", doc.attr("xmlns"), svgNS))
	v.check("SVG Version 1.2", v.Version == "1.2", true,
		fmt.Sprintf(`Root declares version=%q; BIMI requires "1.2".`, v.Version))
	v.check("SVG Profile Tiny P/S", strings.EqualFold(v.BaseProfile, "tiny-ps"), true,
		fmt.Sprintf(`Root declares baseProfile=%q; BIMI requires "tiny-ps".`, v.BaseProfile))
	v.check("Square Aspect Ratio (1:1)", v.SquareAspect, true,
		fmt.Sprintf("Root declares viewBox=%q; BIMI requires min-x min-y width height with equal, positive width and height.", v.ViewBox))
	v.check("No Scripts or Embedded Content", len(doc.forbidden) == 0, false, forbidden)
	v.check("No Inline Event Handlers", !doc.handlers, false,
		"Event attributes such as onload or onclick are prohibited.")
	v.check("No JavaScript URIs", !doc.jsURI, false,
		"javascript: URIs are prohibited.")
	v.check("No External Network Resources", !doc.external, false,
		"Remote links, stylesheets, fonts and @import are not allowed.")

	v.Compliant = v.FailCount == 0
	if slices.ContainsFunc(v.Findings, func(f BIMIFinding) bool { return f.Fixable }) {
		v.AutoFixedSVG = doc.fixed()
	}
	return v, nil
}

func (v *BIMIValidation) check(rule string, pass, fixable bool, detail string) {
	f := BIMIFinding{Severity: "ok", Rule: rule, Detail: detail}
	if !pass {
		f.Severity, f.Fixable = "fail", fixable
		v.FailCount++
	}
	v.Findings = append(v.Findings, f)
}

// AutoFixBIMI sets the root attributes BIMI requires (namespace, version 1.2, baseProfile
// tiny-ps, a square viewBox) and keeps everything else as written, so content violations
// such as scripts are left for the author to remove.
func AutoFixBIMI(rawSVG string) (string, error) {
	doc, err := parseSVG(rawSVG)
	if err != nil {
		return "", err
	}
	return doc.fixed(), nil
}

// svgDoc is what one decoder pass learns about an SVG document.
type svgDoc struct {
	src                       string
	root                      xml.StartElement // prefixes as written
	rootStart, rootEnd        int64            // byte span of the root start tag in src
	forbidden                 []string
	handlers, jsURI, external bool
}

func parseSVG(rawSVG string) (*svgDoc, error) {
	doc := &svgDoc{src: strings.TrimSpace(rawSVG)}
	if doc.src == "" {
		return nil, errors.New("empty SVG content")
	}
	dec := xml.NewDecoder(strings.NewReader(doc.src))
	for {
		start := dec.InputOffset()
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("malformed XML: %w", err)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if doc.rootEnd == 0 {
				if t.Name.Local != "svg" {
					return nil, fmt.Errorf("root element is <%s>, expected <svg>", t.Name.Local)
				}
				doc.rootStart, doc.rootEnd = start, dec.InputOffset()
			}
			doc.scan(t)
		case xml.CharData:
			doc.external = doc.external || reCSSFetch.Match(t)
		}
	}
	if doc.rootEnd == 0 {
		return nil, errors.New("no XML root element found")
	}
	// Token resolves prefixes to namespace URLs; the raw root tag keeps them as written.
	root, err := xml.NewDecoder(strings.NewReader(doc.src[doc.rootStart:doc.rootEnd])).RawToken()
	if err != nil {
		return nil, fmt.Errorf("malformed XML: %w", err)
	}
	doc.root = root.(xml.StartElement)
	return doc, nil
}

func (d *svgDoc) scan(el xml.StartElement) {
	for _, name := range bimiForbidden {
		if strings.EqualFold(el.Name.Local, name) && !slices.Contains(d.forbidden, name) {
			d.forbidden = append(d.forbidden, name)
		}
	}
	for _, a := range el.Attr {
		d.handlers = d.handlers || strings.HasPrefix(strings.ToLower(a.Name.Local), "on")
		d.jsURI = d.jsURI || strings.HasPrefix(strings.ToLower(strings.TrimSpace(a.Value)), "javascript:")
		d.external = d.external || reCSSFetch.MatchString(a.Value) ||
			a.Name.Local == "href" && reNetworkURL.MatchString(a.Value)
	}
}

func (d *svgDoc) attr(name string) string {
	for _, a := range d.root.Attr {
		if qualified(a.Name) == name {
			return a.Value
		}
	}
	return ""
}

func qualified(n xml.Name) string {
	if n.Space == "" {
		return n.Local
	}
	return n.Space + ":" + n.Local
}

// fixed rewrites only the root start tag; the prolog and body stay byte-for-byte.
func (d *svgDoc) fixed() string {
	attrs := slices.Clone(d.root.Attr)
	for _, want := range []xml.Attr{
		{Name: xml.Name{Local: "xmlns"}, Value: svgNS},
		{Name: xml.Name{Local: "version"}, Value: "1.2"},
		{Name: xml.Name{Local: "baseProfile"}, Value: "tiny-ps"},
		{Name: xml.Name{Local: "viewBox"}, Value: d.squareViewBox()},
	} {
		if i := slices.IndexFunc(attrs, func(a xml.Attr) bool { return a.Name == want.Name }); i >= 0 {
			attrs[i].Value = want.Value
		} else {
			attrs = append(attrs, want)
		}
	}

	var b strings.Builder
	b.WriteString(d.src[:d.rootStart])
	b.WriteString("<" + qualified(d.root.Name))
	for _, a := range attrs {
		b.WriteString(" " + qualified(a.Name) + `="`)
		xml.EscapeText(&b, []byte(a.Value))
		b.WriteByte('"')
	}
	if strings.HasSuffix(d.src[:d.rootEnd], "/>") {
		b.WriteString("/>")
	} else {
		b.WriteByte('>')
	}
	b.WriteString(d.src[d.rootEnd:])
	return b.String()
}

// squareViewBox grows the short side of the viewBox around its centre. Without a usable
// viewBox it starts from width and height, and failing those from 512x512.
func (d *svgDoc) squareViewBox() string {
	box, ok := parseViewBox(d.attr("viewBox"))
	if !ok {
		w, wok := parseFinite(strings.TrimSuffix(strings.TrimSpace(d.attr("width")), "px"))
		h, hok := parseFinite(strings.TrimSuffix(strings.TrimSpace(d.attr("height")), "px"))
		if !wok || !hok || w <= 0 || h <= 0 {
			w, h = 512, 512
		}
		box = [4]float64{0, 0, w, h}
	}
	side := max(box[2], box[3])
	return fmt.Sprintf("%g %g %g %g", box[0]-(side-box[2])/2, box[1]-(side-box[3])/2, side, side)
}

// parseViewBox reads "min-x min-y width height", separated by spaces and/or commas;
// ok needs finite numbers and a positive width and height.
func parseViewBox(s string) (box [4]float64, ok bool) {
	fields := strings.FieldsFunc(s, func(r rune) bool { return r == ',' || unicode.IsSpace(r) })
	if len(fields) != 4 {
		return box, false
	}
	for i, f := range fields {
		if box[i], ok = parseFinite(f); !ok {
			return box, false
		}
	}
	return box, box[2] > 0 && box[3] > 0
}

func parseFinite(s string) (float64, bool) {
	v, err := strconv.ParseFloat(s, 64)
	return v, err == nil && !math.IsInf(v, 0) && !math.IsNaN(v)
}
