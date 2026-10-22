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

// Spamhaus DROP is free, commercial use too, if credited with its copyright and date kept with the
// data: dropEntry's Meta and the footer do both. IPv4 only, since range bounds are uint32.

const (
	// DROP+EDROP (merged since 2024) as JSON Lines; a trailing metadata row carries copyright and terms.
	dropURL = "https://www.spamhaus.org/drop/drop_v4.json"

	dropHTTPTimeout = 60 * time.Second

	dropUpsertChunk = 5000
)

var dropHTTPClient = &http.Client{Timeout: dropHTTPTimeout}

// dropRecord covers both line shapes (CIDR row, metadata row) so each line needs one unmarshal.
type dropRecord struct {
	Type      string `json:"type"` // "metadata" on trailing record; "" on CIDR rows
	CIDR      string `json:"cidr"`
	SBLID     string `json:"sblid"`
	RIR       string `json:"rir"`
	Timestamp int64  `json:"timestamp"`
	Copyright string `json:"copyright"`
	Terms     string `json:"terms"`
}

type dropMeta struct {
	Copyright string
	Terms     string
	Timestamp time.Time
}

func SyncSpamhausDROP(ctx context.Context, bl *BlockList) (BlockSyncResult, error) {
	return bl.syncFeed(ctx, BlocklistSourceSpamhausDROP, dropUpsertChunk,
		func(ctx context.Context) (io.ReadCloser, error) {
			return fetchFeed(ctx, dropHTTPClient, dropURL, "spamhaus DROP feed")
		},
		parseDROP,
	)
}

// RunSpamhausDROPSync syncs now, then daily until ctx ends; run it as a goroutine from main.
func RunSpamhausDROPSync(ctx context.Context, bl *BlockList) {
	runDailySync(ctx, bl, "spamhaus DROP", "netblocks", SyncSpamhausDROP)
}

// Entries are built after the whole read: the metadata row comes last but must reach every entry.
func parseDROP(r io.Reader) ([]BlockEntry, error) {
	var (
		raw  []dropRecord
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
			continue
		}
		if rec.Type == "metadata" {
			meta = dropMeta{Copyright: rec.Copyright, Terms: rec.Terms}
			if rec.Timestamp > 0 {
				meta.Timestamp = time.Unix(rec.Timestamp, 0).UTC()
			}
			continue
		}
		if rec.CIDR == "" {
			continue
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
