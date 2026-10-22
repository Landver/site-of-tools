package linktools

import (
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Extraction is every URL found in pasted text (A18); nothing is fetched, unlike the surveyed tools.
type Extraction struct {
	URLs   []ExtractedURL `json:"urls"`
	Total  int            `json:"total"`  // occurrences listed, before de-duplication
	Unique int            `json:"unique"` // == len(URLs)
	Source string         `json:"source"` // how the input was read: html, markdown, text
	Notes  []Note         `json:"notes,omitempty"`
}

// ExtractedURL is one distinct URL in first-seen order; Flags are what its text alone says to worry about.
type ExtractedURL struct {
	URL       string   `json:"url"`
	Anchor    string   `json:"anchor,omitempty"`    // first non-empty link text, whitespace collapsed
	Anchors   []string `json:"anchors,omitempty"`   // every distinct link text, first one first, capped
	Count     int      `json:"count"`               // occurrences, including the first
	Positions []int    `json:"positions,omitempty"` // byte offsets into the input, capped
	Flags     []Note   `json:"flags,omitempty"`
}

// Source values, named rather than inlined because the template branches on them.
const (
	SourceHTML     = "html"
	SourceMarkdown = "markdown"
	SourceText     = "text"
)

const (
	// maxExtractInput caps what is scanned: the route is unauthenticated and a megabyte is a cheap DoS.
	maxExtractInput = 1 << 20
	// maxExtractURLs caps the table: past two thousand rows no human reads the page.
	maxExtractURLs = 2000
	// maxPositions caps one row's offsets; Count stays exact.
	maxPositions = 100
	// maxAnchorText keeps one runaway link text from owning the table.
	maxAnchorText = 200
	maxAnchors    = 5
)

// Extract lists every URL in text, deduped; relative links stay as written, as resolving needs a base URL.
func (s *Service) Extract(text string) (*Extraction, error) {
	if strings.TrimSpace(text) == "" {
		return nil, fmt.Errorf("no text given")
	}

	out := &Extraction{}
	if len(text) > maxExtractInput {
		text = truncateUTF8(text, maxExtractInput)
		out.Notes = append(out.Notes, Note{SevWarn, "Only part of the input was read",
			fmt.Sprintf("The first %d KB were scanned and the rest was not. Links past the cut are missing from this table, not absent from your text.", maxExtractInput>>10)})
	}

	out.Source = detectSource(text)
	var hits []found
	switch out.Source {
	case SourceHTML:
		hits = extractHTML(text)
	case SourceMarkdown:
		hits = extractMarkdown(text)
	default:
		hits = extractBare(text, 0)
	}

	seen := make(map[string]int, len(hits))
	for _, f := range hits {
		u := strings.TrimSpace(f.url)
		if u == "" || strings.HasPrefix(u, "#") {
			// "" and "#top" aren't inspectable; "javascript:…" stays: showing it is what this suite is for.
			continue
		}
		if i, ok := seen[u]; ok {
			row := &out.URLs[i]
			row.Count++
			out.Total++
			row.addAnchor(tidyAnchor(f.anchor))
			if len(row.Positions) < maxPositions {
				row.Positions = append(row.Positions, f.pos)
			}
			continue
		}
		if len(out.URLs) >= maxExtractURLs {
			continue
		}
		seen[u] = len(out.URLs)
		row := ExtractedURL{URL: u, Count: 1, Positions: []int{f.pos}}
		row.addAnchor(tidyAnchor(f.anchor))
		out.URLs = append(out.URLs, row)
		out.Total++
	}

	worth := 0 // rows with something more than a note
	for i := range out.URLs {
		row := &out.URLs[i]
		row.Flags = auditLink(row.URL, row.Anchors)
		for _, f := range row.Flags {
			if f.Severity == SevFail || f.Severity == SevWarn {
				worth++
				break
			}
		}
	}
	if worth > 0 {
		out.Notes = append(out.Notes, Note{SevWarn, plural(worth, "link") + " worth a second look",
			"Marked in the table below: what each one shows against where it goes, wrappers, and schemes that run code instead of going anywhere."})
	}

	out.Unique = len(out.URLs)
	if out.Unique >= maxExtractURLs {
		out.Notes = append(out.Notes, Note{SevWarn, "The list stops at " + fmt.Sprint(maxExtractURLs),
			"More distinct URLs were found than are shown. The ones listed are the first ones in the text."})
	}
	if out.Unique == 0 {
		out.Notes = append(out.Notes, Note{SevInfo, "No links found",
			"Nothing here parsed as a URL. Links written without https:// (like example.com/thing) are skipped on purpose: guessing the scheme invents links that were never there."})
	}
	return out, nil
}

// addAnchor keeps every distinct text, not just the first: two texts are two claims about the destination.
func (r *ExtractedURL) addAnchor(a string) {
	if a == "" || slices.Contains(r.Anchors, a) || len(r.Anchors) >= maxAnchors {
		return
	}
	if r.Anchor == "" {
		r.Anchor = a
	}
	r.Anchors = append(r.Anchors, a)
}

// auditLink flags a link from its text alone; nothing is fetched or resolved.
func auditLink(raw string, anchors []string) []Note {
	u, err := url.Parse(raw)
	if err != nil {
		return []Note{{SevWarn, "Not a valid URL", parseReason(err).Error()}}
	}
	var notes []Note
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	switch {
	case isDangerousScheme(scheme):
		notes = append(notes, Note{SevFail, scheme + ": link",
			"Runs or embeds something instead of going anywhere. Nothing that is sent out should carry one."})
	case scheme == "" && host == "":
		notes = append(notes, Note{SevInfo, "Relative link",
			"Where it goes depends on the page it ends up on; in an email it usually goes nowhere."})
	}
	if u.User != nil && host != "" {
		notes = append(notes, Note{SevFail, "Credentials before the host",
			"Everything before the @ is a username. This goes to " + host + "."})
	}
	// Only text that reads as a URL or domain makes a claim to compare.
	for _, a := range anchors {
		if shown := hostInText(a); shown != "" && host != "" && !sameSite(shown, host) {
			notes = append(notes, Note{SevFail, "Text shows " + shown + ", link goes to " + host,
				"What the reader sees is not where the click goes."})
			break
		}
	}
	if target, name, partial, ok := unwrapAll(raw); ok || partial {
		dest := "a destination it does not reveal"
		if t, err := url.Parse(target); err == nil && t.Hostname() != "" {
			dest = t.Hostname()
		} else if partial && target != "" {
			dest = target
		}
		notes = append(notes, Note{SevWarn, name + " wrapper, really goes to " + dest,
			"Unwrapped from the link text, not fetched. The wrapper vouches for nothing about the destination."})
	}
	trackers := 0
	for _, pair := range strings.Split(u.RawQuery, "&") {
		k, _, _ := strings.Cut(pair, "=")
		if key, err := url.QueryUnescape(k); err == nil && key != "" && TrackingRuleFor(key) != "" {
			trackers++
		}
	}
	if trackers > 0 {
		notes = append(notes, Note{SevInfo, plural(trackers, "tracking parameter"), "Clean would remove them."})
	}
	return notes
}

// textHostRe: link text that reads as a bare domain, optionally with a path.
var textHostRe = regexp.MustCompile(`(?i)^(?:www\.)?[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}(?:[/?#]\S*)?$`)

// hostInText is the host a link text claims to be, or "".
func hostInText(a string) string {
	a = strings.TrimSpace(a)
	if strings.Contains(a, "://") {
		if u, err := url.Parse(a); err == nil {
			return strings.ToLower(u.Hostname())
		}
		return ""
	}
	if !textHostRe.MatchString(a) {
		return ""
	}
	host, _, _ := strings.Cut(a, "/")
	host, _, _ = strings.Cut(host, "?")
	host, _, _ = strings.Cut(host, "#")
	return strings.ToLower(host)
}

// sameSite: the link goes where its text says or to a subdomain; paypal.com.example.net is not paypal.com.
func sameSite(shown, host string) bool {
	shown, host = strings.TrimPrefix(shown, "www."), strings.TrimPrefix(host, "www.")
	return host == shown || strings.HasSuffix(host, "."+shown)
}

// found is one URL as located in the input, before de-duplication.
type found struct {
	url    string
	anchor string
	pos    int
}

var (
	// htmlishRe is deliberately narrow: Markdown has stray angle brackets, and <https://x> is not markup.
	htmlishRe = regexp.MustCompile(`(?is)<(?:!doctype\s+html|html[\s>]|/?(?:body|head|div|p|table|td|tr|span|br)[\s/>]|[a-z][a-z0-9]*\s[^<>]*\b(?:href|src|action)\s*=)`)
	// mdLinkRe: "[text](url)"; the <> target is a separate branch, being the only form allowed a space.
	mdLinkRe = regexp.MustCompile(`\[([^\]\n]*)\]\(\s*(?:<([^>\n]*)>|([^)\s<>]*))(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?\s*\)`)
	// bareURLRe stops at quotes, angle brackets and braces; parentheses stay in and are balanced afterwards.
	bareURLRe = regexp.MustCompile("(?i)\\b(?:(?:https?|ftps?|wss?)://|mailto:)[^\\s<>\"'`{}|\\\\^\\[\\]]+")
)

// detectSource picks the reader: Markdown read as text loses anchors, HTML read as text finds <script> URLs.
func detectSource(text string) string {
	switch {
	case htmlishRe.MatchString(text):
		return SourceHTML
	case mdLinkRe.MatchString(text):
		return SourceMarkdown
	default:
		return SourceText
	}
}

// extractHTML uses the tokeniser, not html.Parse, so a malformed fragment reads as written, not as repaired.
// Offsets sum Raw() lengths; within a text run they are the run's start, as Text() has resolved entities.
func extractHTML(text string) []found {
	var out []found
	z := html.NewTokenizer(strings.NewReader(text))
	var anchorText strings.Builder
	inAnchor, pending, pendingLabel, pendingPos := false, "", "", 0
	offset := 0

	// flush closes the open <a>, also at EOF: an unclosed <a> still had an href.
	flush := func() {
		if !inAnchor {
			return
		}
		label := anchorText.String()
		if strings.TrimSpace(label) == "" {
			label = pendingLabel // an image-only link: fall back to title/alt
		}
		out = append(out, found{url: pending, anchor: label, pos: pendingPos})
		inAnchor, pending, pendingLabel = false, "", ""
		anchorText.Reset()
	}

	for {
		tt := z.Next()
		start := offset
		// Take the length first: TagName and TagAttr below reuse Raw's backing array.
		offset += len(z.Raw())

		switch tt {
		case html.ErrorToken:
			flush()
			return out
		case html.TextToken:
			if inAnchor {
				anchorText.Write(z.Text())
				continue
			}
			// A bare URL in page text still counts; inside an <a> it would count the href twice.
			out = append(out, extractBare(string(z.Text()), start)...)
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			tag := strings.ToLower(string(name))
			var link, label string
			for hasAttr {
				var k, v []byte
				k, v, hasAttr = z.TagAttr()
				switch strings.ToLower(string(k)) {
				case "href", "src", "action":
					if link == "" {
						link = string(v)
					}
				case "alt", "title":
					if label == "" {
						label = string(v)
					}
				}
			}
			if tag == "a" && tt == html.StartTagToken {
				flush()
				inAnchor, pending, pendingLabel, pendingPos = true, link, label, start
				continue
			}
			if link != "" {
				out = append(out, found{url: link, anchor: label, pos: start})
			}
		case html.EndTagToken:
			if name, _ := z.TagName(); strings.EqualFold(string(name), "a") {
				flush()
			}
		}
	}
}

// extractMarkdown blanks link spans before the bare scan so no URL counts twice, then merges by position.
func extractMarkdown(text string) []found {
	var out []found
	rest := []byte(text)
	for _, m := range mdLinkRe.FindAllStringSubmatchIndex(text, -1) {
		target := ""
		if m[4] >= 0 { // <…> form
			target = text[m[4]:m[5]]
		} else if m[6] >= 0 {
			target = text[m[6]:m[7]]
		}
		out = append(out, found{url: target, anchor: text[m[2]:m[3]], pos: m[0]})
		for i := m[0]; i < m[1]; i++ {
			rest[i] = ' '
		}
	}
	out = append(out, extractBare(string(rest), 0)...)
	slices.SortStableFunc(out, func(a, b found) int { return a.pos - b.pos })
	return out
}

// extractBare finds scheme-carrying URLs, offsets shifted by base; a bare "www.x.com" is never guessed at.
func extractBare(text string, base int) []found {
	var out []found
	for _, m := range bareURLRe.FindAllStringIndex(text, -1) {
		if u := trimTrailingPunct(text[m[0]:m[1]]); u != "" {
			out = append(out, found{url: u, pos: base + m[0]})
		}
	}
	return out
}

// trimTrailingPunct balances ')': "…/Go_(language)" is a URL, "(see https://x.com/a)" is a sentence.
func trimTrailingPunct(s string) string {
	for len(s) > 0 {
		switch s[len(s)-1] {
		case '.', ',', ';', ':', '!', '?', '"', '\'':
			s = s[:len(s)-1]
		case ')':
			if strings.Count(s, ")") <= strings.Count(s, "(") {
				return s
			}
			s = s[:len(s)-1]
		default:
			return s
		}
	}
	return s
}

// tidyAnchor collapses link text to one capped line so alt text can't push the URL off screen.
func tidyAnchor(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxAnchorText {
		s = truncateUTF8(s, maxAnchorText-1) + "…"
	}
	return s
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune.
func truncateUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for i := n; i > n-utf8.UTFMax && i > 0; i-- {
		if r, _ := utf8.DecodeLastRuneInString(s[:i]); r != utf8.RuneError {
			return s[:i]
		}
	}
	return s[:n]
}
