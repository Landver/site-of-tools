package iptools

import (
	"strings"
	"testing"
	"time"
)

// White-box (package iptools) because parseIPsum and its helpers are
// unexported — the CLAUDE.md-sanctioned exception for testing internals that
// don't need to be public. Keeps the network-free parse logic covered without
// hitting GitHub.

func TestParseIPsum(t *testing.T) {
	feed := strings.Join([]string{
		"# IPsum Threat Intelligence Feed",
		"# (https://github.com/stamparm/ipsum)",
		"#",
		"# Last update: Tue, 21 Jul 2026 03:00:58 +0200",
		"#",
		"# IP\tnumber of (black)lists",
		"#",
		"77.90.185.20\t11",
		"1.2.3.4\t3",
		"2001:db8::1\t5", // IPv6 is valid too
		"",               // blank line skipped
		"not-an-ip\t4",   // malformed IP skipped
		"9.9.9.9\tNaN",   // malformed count skipped
		"8.8.8.8",        // missing count skipped
	}, "\n")

	entries, feedTime, err := parseIPsum(strings.NewReader(feed))
	if err != nil {
		t.Fatalf("parseIPsum: %v", err)
	}
	if len(entries) != 3 {
		t.Fatalf("parsed %d entries, want 3 (garbage rows must be skipped): %+v", len(entries), entries)
	}

	want := time.Date(2026, 7, 21, 3, 0, 58, 0, time.FixedZone("", 2*3600))
	if !feedTime.Equal(want) {
		t.Errorf("feed time = %v, want %v", feedTime, want)
	}

	// First entry carries the count, the ipsum source, a reason, and preserves
	// the feed timestamp + URL in meta (nothing ipsum exposes is dropped).
	e := entries[0]
	if e.IP != "77.90.185.20" || e.Count != 11 || e.Source != BlocklistSourceIPsum {
		t.Errorf("entry[0] = %+v, want ip=77.90.185.20 count=11 source=ipsum", e)
	}
	if e.Reason == "" {
		t.Errorf("entry[0] has no reason")
	}
	if _, ok := e.Meta["feed_updated_at"]; !ok {
		t.Errorf("entry[0] meta missing feed_updated_at: %+v", e.Meta)
	}
	if e.Meta["feed_url"] != ipsumURL {
		t.Errorf("entry[0] meta feed_url = %v, want %q", e.Meta["feed_url"], ipsumURL)
	}
}

// TestParseIPsumNoHeaderTime: a feed without the "Last update" header still
// parses; entries just carry no feed_updated_at (zero time is omitted).
func TestParseIPsumNoHeaderTime(t *testing.T) {
	entries, feedTime, err := parseIPsum(strings.NewReader("5.6.7.8\t4\n"))
	if err != nil {
		t.Fatalf("parseIPsum: %v", err)
	}
	if !feedTime.IsZero() {
		t.Errorf("feed time = %v, want zero", feedTime)
	}
	if len(entries) != 1 {
		t.Fatalf("parsed %d entries, want 1", len(entries))
	}
	if _, ok := entries[0].Meta["feed_updated_at"]; ok {
		t.Errorf("entry should omit feed_updated_at when the feed carries no timestamp: %+v", entries[0].Meta)
	}
}
