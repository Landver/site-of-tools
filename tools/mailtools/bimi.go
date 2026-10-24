package mailtools

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
)

const maxBIMIFileSize = 32 * 1024 // 32 KB strict BIMI size limit

// BIMIFinding models an issue or validation pass for BIMI compliance.
type BIMIFinding struct {
	Severity string `json:"severity"` // "fail", "warn", "ok", "info"
	Rule     string `json:"rule"`
	Detail   string `json:"detail"`
	Fixable  bool   `json:"fixable"`
}

// BIMIValidation holds the validation audit result for an SVG logo.
type BIMIValidation struct {
	Compliant      bool          `json:"compliant"`
	FileSize       int           `json:"file_size"`
	Version        string        `json:"version,omitempty"`
	BaseProfile    string        `json:"base_profile,omitempty"`
	ViewBox        string        `json:"viewbox,omitempty"`
	AspectRatio    string        `json:"aspect_ratio,omitempty"`
	SquareAspect   bool          `json:"square_aspect"`
	Findings       []BIMIFinding `json:"findings"`
	FailCount      int           `json:"fail_count"`
	WarnCount      int           `json:"warn_count"`
	SanitizedSVG   string        `json:"sanitized_svg,omitempty"`
	AutoFixedSVG   string        `json:"auto_fixed_svg,omitempty"`
	CanAutoFix     bool          `json:"can_auto_fix"`
}

var (
	reScriptTag    = regexp.MustCompile(`(?i)<\s*script[^>]*>[\s\S]*?<\s*/\s*script\s*>`)
	reForeignObj   = regexp.MustCompile(`(?i)<\s*foreignObject[^>]*>[\s\S]*?<\s*/\s*foreignObject\s*>`)
	reEventHandler = regexp.MustCompile(`(?i)(?:[\s/]+)on[a-z]+\s*=\s*("[^"]*"|'[^']*'|[^\s>]+)`)
	reJSURI        = regexp.MustCompile(`(?i)(href|xlink:href)\s*=\s*["']\s*javascript:[^"']*["']`)
	reExternalURL  = regexp.MustCompile(`(?i)url\s*\(\s*["']?https?://[^"')]+["']?\s*\)`)
	reImportCSS    = regexp.MustCompile(`(?i)@import\s+[^;]+;`)
	reViewBox      = regexp.MustCompile(`(?i)viewBox\s*=\s*["']([^"']+)["']`)
	reWidth        = regexp.MustCompile(`(?i)\bwidth\s*=\s*["']?([0-9.]+)(?:px)?["']?`)
	reHeight       = regexp.MustCompile(`(?i)\bheight\s*=\s*["']?([0-9.]+)(?:px)?["']?`)
)

// ValidateBIMI audits raw SVG text against the strict BIMI SVG Tiny P/S profile.
func ValidateBIMI(rawSVG string) (*BIMIValidation, error) {
	rawBytes := []byte(strings.TrimSpace(rawSVG))
	if len(rawBytes) == 0 {
		return nil, errors.New("empty SVG content")
	}

	val := &BIMIValidation{
		FileSize: len(rawBytes),
	}

	// Rule 1: File size limit (32 KB)
	if len(rawBytes) > maxBIMIFileSize {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "File Size Limit (<= 32 KB)",
			Detail:   fmt.Sprintf("SVG file size is %d bytes, exceeding the 32 KB (32,768 bytes) BIMI limit.", len(rawBytes)),
			Fixable:  false,
		})
	} else {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "ok",
			Rule:     "File Size Limit (<= 32 KB)",
			Detail:   fmt.Sprintf("SVG file size is %d bytes (within 32 KB limit).", len(rawBytes)),
		})
	}

	// Rule 2: XML Well-formedness
	decoder := xml.NewDecoder(bytes.NewReader(rawBytes))
	var rootToken *xml.StartElement
	hasScript := false
	hasForeign := false
	hasForbiddenTag := false
	var forbiddenTagName string

	for {
		tok, err := decoder.Token()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("malformed XML: %w", err)
		}
		switch elem := tok.(type) {
		case xml.StartElement:
			name := strings.ToLower(elem.Name.Local)
			if rootToken == nil {
				e := elem.Copy()
				rootToken = &e
				if name != "svg" {
					return nil, fmt.Errorf("root element is <%s>, expected <svg>", elem.Name.Local)
				}
			}
			if name == "script" {
				hasScript = true
			}
			if name == "foreignobject" {
				hasForeign = true
			}
			if name == "iframe" || name == "canvas" || name == "audio" || name == "video" || name == "object" || name == "embed" {
				hasForbiddenTag = true
				forbiddenTagName = name
			}
		}
	}

	if rootToken == nil {
		return nil, errors.New("no XML root element found")
	}

	// Parse root element attributes
	attrMap := make(map[string]string)
	for _, attr := range rootToken.Attr {
		attrMap[strings.ToLower(attr.Name.Local)] = attr.Value
	}

	val.Version = attrMap["version"]
	val.BaseProfile = attrMap["baseprofile"]
	val.ViewBox = attrMap["viewbox"]

	// Rule 3: version="1.2"
	if val.Version == "1.2" {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "ok",
			Rule:     "SVG Version 1.2",
			Detail:   "Root specifies version=\"1.2\" as required by BIMI.",
		})
	} else {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "SVG Version 1.2",
			Detail:   fmt.Sprintf("Root specifies version=%q, but BIMI mandates version=\"1.2\".", val.Version),
			Fixable:  true,
		})
	}

	// Rule 4: baseProfile="tiny-ps"
	if strings.EqualFold(val.BaseProfile, "tiny-ps") {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "ok",
			Rule:     "SVG Profile Tiny P/S",
			Detail:   "Root specifies baseProfile=\"tiny-ps\".",
		})
	} else {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "SVG Profile Tiny P/S",
			Detail:   fmt.Sprintf("Root specifies baseProfile=%q, but BIMI mandates baseProfile=\"tiny-ps\".", val.BaseProfile),
			Fixable:  true,
		})
	}

	// Rule 5: viewBox and 1:1 Aspect Ratio
	if val.ViewBox != "" {
		vbParts := strings.Fields(val.ViewBox)
		parsed := false
		if len(vbParts) == 4 {
			w, errW := strconv.ParseFloat(vbParts[2], 64)
			h, errH := strconv.ParseFloat(vbParts[3], 64)
			if errW == nil && errH == nil && w > 0 && h > 0 {
				parsed = true
				val.AspectRatio = fmt.Sprintf("%.0f:%.0f", w, h)
				if w == h {
					val.SquareAspect = true
					val.Findings = append(val.Findings, BIMIFinding{
						Severity: "ok",
						Rule:     "Square Aspect Ratio (1:1)",
						Detail:   fmt.Sprintf("viewBox dimensions are square (%.0f x %.0f).", w, h),
					})
				} else {
					val.Findings = append(val.Findings, BIMIFinding{
						Severity: "fail",
						Rule:     "Square Aspect Ratio (1:1)",
						Detail:   fmt.Sprintf("viewBox dimensions are not 1:1 square (width=%.0f, height=%.0f). Mail clients require 1:1 square logos.", w, h),
						Fixable:  true,
					})
				}
			}
		}
		if !parsed {
			val.Findings = append(val.Findings, BIMIFinding{
				Severity: "fail",
				Rule:     "Square Aspect Ratio (1:1)",
				Detail:   fmt.Sprintf("Invalid or non-positive viewBox %q. Must specify 4 positive numeric values (min-x min-y width height).", val.ViewBox),
				Fixable:  true,
			})
		}
	} else {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "viewBox Attribute",
			Detail:   "Missing viewBox attribute on root <svg> element.",
			Fixable:  true,
		})
	}

	// Rule 6: Prohibited tags
	if hasScript {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "No Executable Scripts",
			Detail:   "<script> elements are strictly forbidden in BIMI logos for security.",
			Fixable:  true,
		})
	}
	if hasForeign {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "No foreignObject",
			Detail:   "<foreignObject> is prohibited in SVG Tiny P/S.",
			Fixable:  true,
		})
	}
	if hasForbiddenTag {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     fmt.Sprintf("Forbidden <%s> element", forbiddenTagName),
			Detail:   fmt.Sprintf("<%s> tags are not permitted in SVG Tiny P/S.", forbiddenTagName),
			Fixable:  true,
		})
	}

	// Rule 7: Event handlers & javascript: URIs
	rawStr := string(rawBytes)
	if reEventHandler.MatchString(rawStr) {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "No Inline Event Handlers",
			Detail:   "Inline event attributes (onclick, onload, etc.) are strictly prohibited.",
			Fixable:  true,
		})
	}
	if reJSURI.MatchString(rawStr) {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "No JavaScript URIs",
			Detail:   "javascript: pseudo-protocols in links are strictly prohibited.",
			Fixable:  true,
		})
	}
	if reExternalURL.MatchString(rawStr) || reImportCSS.MatchString(rawStr) {
		val.Findings = append(val.Findings, BIMIFinding{
			Severity: "fail",
			Rule:     "No External Network Resources",
			Detail:   "External stylesheets, web fonts, or @import URLs are not allowed.",
			Fixable:  true,
		})
	}

	// Summarize counts
	val.Compliant = true
	canFix := false
	for _, f := range val.Findings {
		if f.Severity == "fail" {
			val.FailCount++
			val.Compliant = false
			if f.Fixable {
				canFix = true
			}
		} else if f.Severity == "warn" {
			val.WarnCount++
		}
	}
	val.CanAutoFix = canFix

	// Produce safe sanitized preview SVG (stripping scripts and event handlers)
	val.SanitizedSVG = sanitizeForPreview(rawStr)

	// Produce Auto-Fixed SVG if needed
	if val.CanAutoFix && !val.Compliant {
		fixed, err := AutoFixBIMI(rawStr)
		if err == nil {
			val.AutoFixedSVG = fixed
		}
	}

	return val, nil
}

// sanitizeForPreview neutralizes XSS risks before rendering in an HTML preview.
func sanitizeForPreview(raw string) string {
	s := raw
	for {
		prev := s
		s = reScriptTag.ReplaceAllString(s, "")
		s = reForeignObj.ReplaceAllString(s, "")
		s = reEventHandler.ReplaceAllString(s, "")
		s = reJSURI.ReplaceAllString(s, "")
		if s == prev {
			break
		}
	}
	return s
}

// AutoFixBIMI cleans and formats raw SVG into fully-compliant BIMI SVG Tiny P/S.
func AutoFixBIMI(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty SVG")
	}

	// 1. Strip dangerous tags, event handlers, and external imports
	s = reImportCSS.ReplaceAllString(sanitizeForPreview(s), "")

	// 2. Parse root <svg ...> tag
	rootStart := strings.Index(s, "<svg")
	if rootStart < 0 {
		return "", errors.New("no <svg> opening tag")
	}
	rootEnd := strings.IndexByte(s[rootStart:], '>')
	if rootEnd < 0 {
		return "", errors.New("unclosed <svg> tag")
	}
	rootEnd += rootStart

	rootTag := s[rootStart : rootEnd+1]
	body := s[rootEnd+1:]

	// Extract or synthesize viewBox
	viewBox := ""
	if m := reViewBox.FindStringSubmatch(rootTag); len(m) > 1 {
		viewBox = m[1]
	}

	// If viewBox missing or not square, check width & height
	var wVal, hVal float64
	if m := reWidth.FindStringSubmatch(rootTag); len(m) > 1 {
		wVal, _ = strconv.ParseFloat(m[1], 64)
	}
	if m := reHeight.FindStringSubmatch(rootTag); len(m) > 1 {
		hVal, _ = strconv.ParseFloat(m[1], 64)
	}

	if viewBox == "" {
		if wVal > 0 && hVal > 0 {
			maxDim := max(wVal, hVal)
			viewBox = fmt.Sprintf("0 0 %.0f %.0f", maxDim, maxDim)
		} else {
			viewBox = "0 0 512 512"
		}
	} else {
		// Make sure viewBox is square
		parts := strings.Fields(viewBox)
		if len(parts) == 4 {
			w, errW := strconv.ParseFloat(parts[2], 64)
			h, errH := strconv.ParseFloat(parts[3], 64)
			if errW == nil && errH == nil && w != h {
				maxDim := max(w, h)
				viewBox = fmt.Sprintf("%s %s %.0f %.0f", parts[0], parts[1], maxDim, maxDim)
			}
		}
	}

	// Reconstruct compliant root <svg>
	cleanRoot := fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps" viewBox="%s">`, viewBox)

	res := cleanRoot + body

	// Basic XML declaration if missing
	if !strings.HasPrefix(res, "<?xml") {
		res = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n" + res
	}

	return res, nil
}
