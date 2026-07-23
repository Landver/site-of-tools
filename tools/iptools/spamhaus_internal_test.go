package iptools

import (
	"strings"
	"testing"
	"time"
)

// White-box (package iptools) because parseDROP and its helpers are
// unexported — same CLAUDE.md-sanctioned exception as ipsum_internal_test.go.
// Keeps the network-free parse logic covered without hitting spamhaus.org.

func TestParseDROP(t *testing.T) {
	feed := strings.Join([]string{
		`{"cidr":"1.10.16.0/20","sblid":"SBL256894","rir":"apnic"}`,
		`{"cidr":"1.19.0.0/16","sblid":"SBL434604","rir":"apnic"}`,
		``,                                     // blank line skipped
		`not json at all`,                      // malformed line skipped
		`{"cidr":"2001:db8::/32","sblid":"x"}`, // IPv6 CIDR: parses as JSON but ipv4RangeBounds rejects it
		`{"sblid":"no-cidr-field"}`,            // missing cidr skipped
		// metadata trails the data rows in the real feed — must still apply to
		// every entry above it, not just ones that come after.
		`{"type":"metadata","timestamp":1784708042,"size":101809,"records":1669,"copyright":"(c) 2026 The Spamhaus Project SLU","terms":"https://www.spamhaus.org/drop/terms/"}`,
	}, "\n")

	entries, err := parseDROP(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseDROP: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("parsed %d entries, want 2 (garbage/IPv6/no-cidr rows skipped): %+v", len(entries), entries)
	}

	e := entries[0]
	if e.IP != "1.10.16.0/20" || e.Source != BlocklistSourceSpamhausDROP {
		t.Errorf("entry[0] = %+v, want ip=1.10.16.0/20 source=spamhaus-drop", e)
	}
	if e.RangeStart == 0 || e.RangeEnd == 0 || e.RangeEnd <= e.RangeStart {
		t.Errorf("entry[0] range bounds not set sanely: start=%d end=%d", e.RangeStart, e.RangeEnd)
	}
	if e.Reason == "" {
		t.Errorf("entry[0] has no reason")
	}
	if e.Count != 0 {
		t.Errorf("entry[0] Count = %d, want 0 (DROP is presence-only, no confidence count)", e.Count)
	}

	// Meta: the record's own sblid/rir, PLUS the feed-level copyright/terms/
	// timestamp — even though metadata trails every data row in the file, it
	// must still reach entry[0] (this is the "date and copy text remain with
	// the file and data" requirement Spamhaus's terms ask for).
	if e.Meta["sblid"] != "SBL256894" || e.Meta["rir"] != "apnic" {
		t.Errorf("entry[0] missing its own sblid/rir: %+v", e.Meta)
	}
	if e.Meta["copyright"] != "(c) 2026 The Spamhaus Project SLU" {
		t.Errorf("entry[0] missing feed copyright: %+v", e.Meta)
	}
	if e.Meta["terms"] != "https://www.spamhaus.org/drop/terms/" {
		t.Errorf("entry[0] missing feed terms URL: %+v", e.Meta)
	}
	wantTime := time.Unix(1784708042, 0).UTC()
	if got, _ := e.Meta["feed_updated_at"].(time.Time); !got.Equal(wantTime) {
		t.Errorf("entry[0] feed_updated_at = %v, want %v", got, wantTime)
	}
	if e.Meta["feed_url"] != dropURL {
		t.Errorf("entry[0] meta feed_url = %v, want %q", e.Meta["feed_url"], dropURL)
	}

	if entries[1].IP != "1.19.0.0/16" || entries[1].Meta["sblid"] != "SBL434604" {
		t.Errorf("entry[1] = %+v, want its own distinct sblid", entries[1])
	}
}

// TestParseDROPNoMetadata: a feed with no trailing metadata record still
// parses the CIDR rows; entries just carry no feed-level copyright/terms/time.
func TestParseDROPNoMetadata(t *testing.T) {
	entries, err := parseDROP(strings.NewReader(`{"cidr":"203.0.113.0/24","sblid":"SBL1","rir":"arin"}` + "\n"))
	if err != nil {
		t.Fatalf("parseDROP: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("parsed %d entries, want 1", len(entries))
	}
	e := entries[0]
	if e.Meta["sblid"] != "SBL1" {
		t.Errorf("own-record meta should still be present: %+v", e.Meta)
	}
	for _, k := range []string{"copyright", "terms", "feed_updated_at"} {
		if _, ok := e.Meta[k]; ok {
			t.Errorf("entry should omit %q when the feed carries no metadata record: %+v", k, e.Meta)
		}
	}
}
