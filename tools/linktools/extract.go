package linktools

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/html"
)

// Extraction is every URL found in a block of pasted text (A18,
// docs/01-feature-inventory.md). It is a front door onto Parse rather than a
// feature of its own: the page's job is to hand each row on to Inspect or Clean.
//
// Nothing here fetches anything. The job is "audit every link in this newsletter
// before it goes out", and the surveyed tools that do it all fetch every URL
// they find (docs/reports/), which is both slower and a different, riskier
// promise.
type Extraction struct {
	URLs   []ExtractedURL `json:"urls"`
	Total  int            `json:"total"`  // occurrences listed, before de-duplication
	Unique int            `json:"unique"` // == len(URLs)
	Source string         `json:"source"` // how the input was read: html, markdown, text
	Notes  []Note         `json:"notes,omitempty"`
}

// ExtractedURL is one distinct URL, in the order it was first seen.
type ExtractedURL struct {
	URL       string `json:"url"`
	Anchor    string `json:"anchor,omitempty"`    // first non-empty link text, whitespace collapsed
	Count     int    `json:"count"`               // occurrences, including the first
	Positions []int  `json:"positions,omitempty"` // byte offsets into the input, capped
}

// Source values, named rather than inlined because the template branches on them.
const (
	SourceHTML     = "html"
	SourceMarkdown = "markdown"
	SourceText     = "text"
)

const (
	// maxExtractInput bounds what is scanned at all. A megabyte is a very large
	// newsletter and a very cheap denial of service; this route is reachable
	// unauthenticated, the same reasoning as url.go's maxInput.
	maxExtractInput = 1 << 20
	// maxExtractURLs bounds the table. Two thousand distinct links is already
	// past the point where a human reads the page, and an input can carry far
	// more than that per megabyte.
	maxExtractURLs = 2000
	// maxPositions bounds one row. Count stays exact; only the offset list stops
	// growing, because a thousand repeats of one URL is a number, not a list.
	maxPositions = 100
	// maxAnchorText keeps one runaway link text from owning the table.
	maxAnchorText = 200
)

// Extract pulls every URL out of pasted text, deduplicated and counted.
//
// It never opens a connection — not to resolve a relative href, not to check
// that a link works. Relative links are listed exactly as written, because
// resolving them would need a base URL this function was not given and guessing
// one would invent links that are not in the input.
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
			// An empty href and a bare "#top" are links on the page but not URLs
			// anyone can inspect. Everything else stays, including
			// "javascript:…", which is precisely what this suite exists to show.
			continue
		}
		if i, ok := seen[u]; ok {
			row := &out.URLs[i]
			row.Count++
			out.Total++
			if row.Anchor == "" {
				row.Anchor = tidyAnchor(f.anchor)
			}
			if len(row.Positions) < maxPositions {
				row.Positions = append(row.Positions, f.pos)
			}
			continue
		}
		if len(out.URLs) >= maxExtractURLs {
			continue
		}
		seen[u] = len(out.URLs)
		out.URLs = append(out.URLs, ExtractedURL{
			URL: u, Anchor: tidyAnchor(f.anchor), Count: 1, Positions: []int{f.pos},
		})
		out.Total++
	}

	out.Unique = len(out.URLs)
	if out.Unique >= maxExtractURLs {
		out.Notes = append(out.Notes, Note{SevWarn, "The list stops at " + fmt.Sprint(maxExtractURLs),
			"More distinct URLs were found than are shown. The ones listed are the first ones in the text."})
	}
	if out.Unique == 0 {
		out.Notes = append(out.Notes, Note{SevInfo, "No URLs found",
			"Read as " + out.Source + ". A bare host like \"example.com\" is not extracted: without a scheme it cannot be told apart from ordinary prose."})
	}
	return out, nil
}

// found is one URL as located in the input, before de-duplication.
type found struct {
	url    string
	anchor string
	pos    int
}

var (
	// htmlishRe: a real tag carrying a real link attribute, or a document
	// preamble. Deliberately narrow — Markdown routinely contains stray angle
	// brackets and an autolink like <https://x> is not markup.
	htmlishRe = regexp.MustCompile(`(?is)<(?:!doctype\s+html|html[\s>]|/?(?:body|head|div|p|table|td|tr|span|br)[\s/>]|[a-z][a-z0-9]*\s[^<>]*\b(?:href|src|action)\s*=)`)
	// mdLinkRe: "[text](url)", with CommonMark's two target spellings — bare, or
	// wrapped in <> — and an optional title after it. The <> form is a separate
	// alternative rather than an optional pair of brackets because it is the
	// only one allowed to contain a space, which is the whole reason CommonMark
	// has it. Nested parentheses in a bare target are not handled; that also
	// needs the <> form.
	mdLinkRe = regexp.MustCompile(`\[([^\]\n]*)\]\(\s*(?:<([^>\n]*)>|([^)\s<>]*))(?:\s+(?:"[^"\n]*"|'[^'\n]*'|\([^)\n]*\)))?\s*\)`)
	// bareURLRe: a scheme-carrying URL in running text. The excluded bytes are
	// the ones that end a URL in prose or in markup — quotes, angle brackets,
	// braces — while parentheses stay in and are balanced afterwards.
	bareURLRe = regexp.MustCompile("(?i)\\b(?:(?:https?|ftps?|wss?)://|mailto:)[^\\s<>\"'`{}|\\\\^\\[\\]]+")
)

// detectSource decides how to read the input, and the answer is reported rather
// than assumed, because reading Markdown as plain text quietly loses every
// anchor text and reading HTML as text finds URLs inside <script> that are not
// links.
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

// extractHTML walks markup with x/net/html's tokeniser and pulls href, src and
// action, plus the anchor text of every <a>.
//
// The tokeniser rather than html.Parse: a paste is usually a fragment and often
// malformed, and a tokeniser reports what is written instead of what a browser
// would repair it into. Positions are the byte offset of the token that carried
// the link, accumulated from Raw() because the tokeniser exposes no offset of
// its own; inside a text run the offset is the run's start, since Text() has
// already resolved entities and its indices no longer map to the input.
func extractHTML(text string) []found {
	var out []found
	z := html.NewTokenizer(strings.NewReader(text))
	var anchorText strings.Builder
	inAnchor, pending, pendingLabel, pendingPos := false, "", "", 0
	offset := 0

	// flush closes the <a> currently open. Called on </a>, on a second <a>
	// before one closed, and at EOF, because an unclosed <a> still had an href.
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
		// Take the length first: Raw's backing array is reused by TagName and
		// TagAttr, which the loop calls below.
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
			// Outside a link, a bare URL in the page text is still a URL
			// someone wants to check. Inside one it would count the href twice.
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

// extractMarkdown pulls "[text](url)" links, then the bare URLs around them.
//
// The inline-link spans are blanked before the bare scan so the same URL is not
// counted twice from inside its own parentheses, and the two sets are merged by
// position so the table still reads in document order.
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

// extractBare finds scheme-carrying URLs in running text. base is added to every
// offset, so a caller scanning one piece of a larger document still reports
// positions into the original.
//
// A bare "www.example.com" is not matched. It is indistinguishable from a
// sentence containing a hostname, and a link extractor that guesses invents
// links that were never in the text.
func extractBare(text string, base int) []found {
	var out []found
	for _, m := range bareURLRe.FindAllStringIndex(text, -1) {
		if u := trimTrailingPunct(text[m[0]:m[1]]); u != "" {
			out = append(out, found{url: u, pos: base + m[0]})
		}
	}
	return out
}

// trimTrailingPunct drops the punctuation that ended the sentence rather than
// the URL.
//
// Parentheses are balanced instead of simply stripped, because
// ".../wiki/Go_(language)" is a real URL and "(see https://x.com/a)" is a real
// sentence, and the only thing telling them apart is whether the closing
// parenthesis has a partner inside the match.
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

// tidyAnchor collapses a link text to one line and caps it. The table shows it
// beside the URL, so a paragraph of alt text would push the URL off the screen.
func tidyAnchor(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxAnchorText {
		s = truncateUTF8(s, maxAnchorText-1) + "…"
	}
	return s
}

// truncateUTF8 cuts s to at most n bytes without splitting a rune, so a
// truncated paste stays valid UTF-8 and the JSON encoder has nothing to repair.
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
