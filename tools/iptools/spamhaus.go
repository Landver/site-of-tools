package iptools

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// spamhaus.go: periodic ingest of the Spamhaus DROP/EDROP list into the shared
// blocklist corpus (blocklist.go). DROP lists whole IPv4 netblocks "hijacked or
// leased by professional spam/cyber-crime operations" — a small (~1,669),
// high-confidence, human-curated set, unlike ipsum's crowd-sourced per-IP
// occurrence counting. Free for all use including commercial, per Spamhaus's
// own terms — see docs/roadmap/ip-reputation.md (G37) for the research. Their
// one condition: credit The Spamhaus Project, and keep the copyright notice +
// date attached to the file and data — this file's Meta stamping on every
// ingested record satisfies that literally (see dropEntry), and the site
// footer credits them too (shared/templates/partials/footer.html).
//
// DROP is CIDR *ranges*, not individual IPs (unlike ipsum): its ~1,669 blocks
// cover ~15 MILLION addresses, so one document per address is not an option —
// entries are stored as netblocks via RangeStart/RangeEnd (blocklist.go), and
// Check matches by containment. Scoped to IPv4 only (drop_v4.json): DROP's
// IPv6 counterpart would need 128-bit range bounds our uint32 representation
// doesn't support — a deliberate, documented non-goal, not silently dropped.
//
// Shared sync/fetch scaffolding (BlockSyncResult, syncFeed, fetchFeed,
// runDailySync) lives in blocklist.go, shared with ipsum.go's identical shape.

const (
	// dropURL: IPv4 DROP+EDROP feed (merged into one list since 2024), JSON
	// Lines format — one CIDR record per line, a trailing {"type":"metadata",…}
	// record carries the copyright/timestamp/terms Spamhaus requires kept with
	// the data.
	dropURL = "https://www.spamhaus.org/drop/drop_v4.json"

	// dropHTTPTimeout bounds the download; feed is tiny (~100 KB).
	dropHTTPTimeout = 60 * time.Second

	// dropUpsertChunk bounds entries per BulkWrite — same reasoning as ipsum's,
	// though DROP's ~1,669 records would fit in one batch anyway.
	dropUpsertChunk = 5000
)

// dropHTTPClient dedicated (not http.DefaultClient), same reasoning as
// ipsumHTTPClient.
var dropHTTPClient = &http.Client{Timeout: dropHTTPTimeout}

// dropRecord unifies both JSON-line shapes the DROP feed uses — a CIDR data
// row and the trailing metadata row — so each line needs exactly ONE
// unmarshal, discriminated after the fact by Type/CIDR being set or empty.
// Whichever shape a given line isn't just decodes its fields to zero values.
type dropRecord struct {
	Type      string `json:"type"` // "metadata" on the one trailing record; "" on every CIDR row
	CIDR      string `json:"cidr"`
	SBLID     string `json:"sblid"`
	RIR       string `json:"rir"`
	Timestamp int64  `json:"timestamp"`
	Copyright string `json:"copyright"`
	Terms     string `json:"terms"`
}

// dropMeta: the feed-level facts carried by the trailing metadata record —
// exactly what Spamhaus's terms require travels with the data (copyright +
// date), plus the terms URL.
type dropMeta struct {
	Copyright string
	Terms     string
	Timestamp time.Time
}

// SyncSpamhausDROP downloads the DROP feed + upserts every netblock under
// source "spamhaus-drop" — a thin wrapper supplying DROP's fetch/parse to
// BlockList.syncFeed (blocklist.go), which owns the shared skip/nil/chunking/
// partial-write behavior every feed sync shares.
func SyncSpamhausDROP(ctx context.Context, bl *BlockList) (BlockSyncResult, error) {
	return bl.syncFeed(ctx, BlocklistSourceSpamhausDROP, dropUpsertChunk,
		func(ctx context.Context) (io.ReadCloser, error) {
			return fetchFeed(ctx, dropHTTPClient, dropURL, "spamhaus DROP feed")
		},
		parseDROP,
	)
}

// RunSpamhausDROPSync runs SyncSpamhausDROP once now (self-skips if fresh),
// then on a daily ticker until ctx is cancelled — a thin wrapper over the
// shared runDailySync (blocklist.go). Launch as a background goroutine from
// main, alongside RunIPsumSync.
func RunSpamhausDROPSync(ctx context.Context, bl *BlockList) {
	runDailySync(ctx, bl, "spamhaus DROP", "netblocks", SyncSpamhausDROP)
}

// parseDROP turns the feed body into range-bound entries. Pure (no Mongo, no
// network) → unit-testable offline. JSON Lines format, not one JSON array —
// each line decoded independently, once, into the unified dropRecord shape.
// Two passes: the metadata record (copyright/timestamp/terms) can appear
// anywhere but in practice trails every CIDR record, so entries are only
// built once the whole file is read and every record can carry it. A line
// that's neither a valid CIDR record nor the metadata record is skipped, not
// fatal — one stray row mustn't abort the sync. An IPv6 CIDR (not expected in
// drop_v4.json, but not trusted blindly) is likewise skipped by
// ipv4RangeBounds' ok=false.
func parseDROP(r io.Reader) ([]BlockEntry, error) {
	var (
		raw  []dropRecord // CIDR data rows only
		meta dropMeta
	)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var rec dropRecord
		if json.Unmarshal([]byte(line), &rec) != nil {
			continue // malformed line skipped, not fatal
		}
		if rec.Type == "metadata" {
			meta = dropMeta{Copyright: rec.Copyright, Terms: rec.Terms}
			if rec.Timestamp > 0 {
				meta.Timestamp = time.Unix(rec.Timestamp, 0).UTC()
			}
			continue
		}
		if rec.CIDR == "" {
			continue // not a CIDR row (e.g. missing the cidr field)
		}
		raw = append(raw, rec)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	entries := make([]BlockEntry, 0, len(raw))
	for _, rec := range raw {
		start, end, ok := ipv4RangeBounds(rec.CIDR)
		if !ok {
			continue
		}
		entries = append(entries, dropEntry(rec, start, end, meta))
	}
	return entries, nil
}

// dropEntry builds the corpus record for one netblock, stashing everything
// Spamhaus's terms require kept "with the file and data": the feed-level
// copyright notice + timestamp + terms URL (meta, shared across every record
// in this sync), plus the record's own sblid/rir.
func dropEntry(rec dropRecord, start, end uint32, meta dropMeta) BlockEntry {
	m := map[string]any{"feed_url": dropURL}
	if rec.SBLID != "" {
		m["sblid"] = rec.SBLID
	}
	if rec.RIR != "" {
		m["rir"] = rec.RIR
	}
	if meta.Copyright != "" {
		m["copyright"] = meta.Copyright
	}
	if meta.Terms != "" {
		m["terms"] = meta.Terms
	}
	if !meta.Timestamp.IsZero() {
		m["feed_updated_at"] = meta.Timestamp
	}
	return BlockEntry{
		IP:         rec.CIDR,
		Source:     BlocklistSourceSpamhausDROP,
		RangeStart: start,
		RangeEnd:   end,
		Reason:     "Netblock hijacked or leased by a professional spam/cyber-crime operation (Spamhaus DROP)",
		Meta:       m,
	}
}
