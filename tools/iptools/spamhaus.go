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

// spamhaus.go: periodic ingest of Spamhaus DROP/EDROP list → shared blocklist
// corpus (blocklist.go). DROP = whole IPv4 netblocks "hijacked or leased by
// professional spam/cyber-crime operations": small (~1,669), high-confidence,
// human-curated — unlike ipsum's crowd-sourced per-IP counting. Free incl.
// commercial per Spamhaus terms; research: docs/roadmap/ip-reputation.md (G37).
// Condition: credit The Spamhaus Project + keep copyright notice + date with
// file/data — Meta stamping on every record satisfies this literally (see
// dropEntry); site footer credits too (shared/templates/partials/footer.html).
//
// DROP = CIDR *ranges*, not per-IP (unlike ipsum): ~1,669 blocks cover ~15M
// addresses → no per-address doc; stored as netblocks via RangeStart/RangeEnd
// (blocklist.go), Check matches by containment. IPv4 only (drop_v4.json): IPv6
// needs 128-bit bounds our uint32 can't hold — deliberate documented non-goal.
//
// Shared sync/fetch scaffolding (BlockSyncResult, syncFeed, fetchFeed,
// runDailySync) in blocklist.go, shared w/ ipsum.go's identical shape.

const (
	// dropURL: IPv4 DROP+EDROP feed (merged since 2024), JSON Lines — one CIDR
	// record/line; trailing {"type":"metadata",…} row carries copyright/
	// timestamp/terms Spamhaus requires kept with data.
	dropURL = "https://www.spamhaus.org/drop/drop_v4.json"

	// dropHTTPTimeout bounds download; feed tiny (~100 KB).
	dropHTTPTimeout = 60 * time.Second

	// dropUpsertChunk bounds entries/BulkWrite — same as ipsum's, though DROP's
	// ~1,669 records fit one batch anyway.
	dropUpsertChunk = 5000
)

// dropHTTPClient dedicated (not http.DefaultClient), same as ipsumHTTPClient.
var dropHTTPClient = &http.Client{Timeout: dropHTTPTimeout}

// dropRecord unifies both DROP JSON-line shapes — CIDR data row + trailing
// metadata row — so each line needs ONE unmarshal, discriminated after by
// Type/CIDR set-or-empty. Fields of the non-matching shape decode to zero.
type dropRecord struct {
	Type      string `json:"type"` // "metadata" on trailing record; "" on CIDR rows
	CIDR      string `json:"cidr"`
	SBLID     string `json:"sblid"`
	RIR       string `json:"rir"`
	Timestamp int64  `json:"timestamp"`
	Copyright string `json:"copyright"`
	Terms     string `json:"terms"`
}

// dropMeta: feed-level facts from trailing metadata record — what Spamhaus
// terms require travel with data (copyright + date) + terms URL.
type dropMeta struct {
	Copyright string
	Terms     string
	Timestamp time.Time
}

// SyncSpamhausDROP downloads DROP feed + upserts every netblock under source
// "spamhaus-drop". Thin wrapper: supplies DROP's fetch/parse to
// BlockList.syncFeed (blocklist.go), which owns shared skip/nil/chunking/
// partial-write behavior.
func SyncSpamhausDROP(ctx context.Context, bl *BlockList) (BlockSyncResult, error) {
	return bl.syncFeed(ctx, BlocklistSourceSpamhausDROP, dropUpsertChunk,
		func(ctx context.Context) (io.ReadCloser, error) {
			return fetchFeed(ctx, dropHTTPClient, dropURL, "spamhaus DROP feed")
		},
		parseDROP,
	)
}

// RunSpamhausDROPSync runs SyncSpamhausDROP once now (self-skips if fresh),
// then daily ticker until ctx cancelled. Thin wrapper over shared runDailySync
// (blocklist.go). Launch as background goroutine from main, alongside
// RunIPsumSync.
func RunSpamhausDROPSync(ctx context.Context, bl *BlockList) {
	runDailySync(ctx, bl, "spamhaus DROP", "netblocks", SyncSpamhausDROP)
}

// parseDROP turns feed body into range-bound entries. Pure (no Mongo/network)
// → unit-testable offline. JSON Lines, not one array — each line decoded once
// into unified dropRecord. Two passes: metadata record can appear anywhere but
// trails every CIDR row in practice, so entries built only after whole file
// read + every record can carry it. Line that's neither valid CIDR nor
// metadata → skipped, not fatal (one stray row mustn't abort sync). IPv6 CIDR
// (not expected in drop_v4.json, not trusted blindly) → skipped via
// ipv4RangeBounds ok=false.
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
			continue // not a CIDR row (missing cidr field)
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

// dropEntry builds corpus record for one netblock, stashing everything
// Spamhaus terms require kept "with file and data": feed-level copyright +
// timestamp + terms URL (meta, shared across sync) + record's own sblid/rir.
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
