package iptools

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ipsum.go: periodic ingest of the stamparm/ipsum threat feed into the shared
// blocklist corpus (blocklist.go). ipsum folds 30+ public blocklists into one
// `IP<TAB>count` file (count = how many lists flag the IP), Unlicense (public
// domain). Download once a day, upsert every listed IP as source "ipsum". One
// writer among many into ip_blocklist — not privileged over a manual/service
// ban.

const (
	// ipsumURL: raw aggregate feed. count column = ipsum's finest published
	// granularity (no per-feed attribution) → count is the most we preserve
	// per IP.
	ipsumURL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

	// ipsumRefreshInterval: feed regenerates daily. Enforced in SyncIPsum (via
	// LastSync), not just the ticker → a restart within the window doesn't
	// re-download.
	ipsumRefreshInterval = 24 * time.Hour

	// ipsumRefreshSlack: guard skips re-download only if the last sync was <
	// (interval - slack) ago. Slack must exceed a sync's own duration so an
	// on-schedule 24h tick — whose completion write lands seconds AFTER the
	// tick — still clears the guard; guarding on the bare interval skips every
	// other tick (→ ~48h cadence). Ample vs a seconds-scale sync.
	ipsumRefreshSlack = 1 * time.Hour

	// ipsumHTTPTimeout bounds the download; feed ~1.8 MB.
	ipsumHTTPTimeout = 60 * time.Second

	// ipsumUpsertChunk bounds entries per BulkWrite → a ~45k-line feed doesn't
	// build one giant command or hold every write model at once.
	ipsumUpsertChunk = 5000
)

// ipsumHTTPClient dedicated (not http.DefaultClient) → the timeout is ours,
// not mutable by other code sharing the default.
var ipsumHTTPClient = &http.Client{Timeout: ipsumHTTPTimeout}

// IPsumSyncResult reports one sync's outcome for logging/tests.
type IPsumSyncResult struct {
	Parsed   int       // valid IP lines parsed
	Written  int       // docs inserted or modified
	Skipped  bool      // corpus fresh (< ipsumRefreshInterval) → no download
	LastSync time.Time // when the corpus was last refreshed (set when Skipped)
}

// SyncIPsum downloads the ipsum feed + upserts every listed IP under source
// "ipsum". Nil-safe (nil bl → zero result, no download). Skips the download
// when the corpus was refreshed within ipsumRefreshInterval → "once a day"
// holds across restarts. Each refresh advances updated_at, keeping still-listed
// IPs alive vs the TTL; an IP that falls off the feed stops being refreshed →
// ages out after blocklistTTL.
func SyncIPsum(ctx context.Context, bl *BlockList) (IPsumSyncResult, error) {
	if bl == nil {
		return IPsumSyncResult{}, nil
	}

	// Staleness guard: skip re-download only if the last sync was recent —
	// threshold is interval MINUS slack, not the bare interval (see
	// ipsumRefreshSlack: guarding on the bare interval skips every other tick).
	// Reads LastSync = newest updated_at, so a PARTIAL prior write (some chunks
	// succeeded, then an error) can read as complete here → a restart inside the
	// window then skips, leaving un-written IPs absent till the next proceeding
	// tick. Accepted: needs a rare mid-batch Mongo failure AND an in-window
	// restart, self-heals next tick, and the 60-day TTL means nothing expires
	// meanwhile — not worth a persisted completion marker.
	if last, err := bl.LastSync(ctx, BlocklistSourceIPsum); err == nil &&
		!last.IsZero() && time.Since(last) < ipsumRefreshInterval-ipsumRefreshSlack {
		return IPsumSyncResult{Skipped: true, LastSync: last}, nil
	}

	body, err := fetchIPsum(ctx)
	if err != nil {
		return IPsumSyncResult{}, err
	}
	defer body.Close()

	entries, _, err := parseIPsum(body)
	if err != nil {
		return IPsumSyncResult{}, err
	}

	res := IPsumSyncResult{Parsed: len(entries)}
	for start := 0; start < len(entries); start += ipsumUpsertChunk {
		end := min(start+ipsumUpsertChunk, len(entries))
		n, err := bl.UpsertMany(ctx, entries[start:end])
		res.Written += n
		if err != nil {
			return res, err
		}
	}
	return res, nil
}

// RunIPsumSync runs SyncIPsum once now (self-skips if fresh), then on a daily
// ticker till ctx is cancelled. Launch as a background goroutine from main. Nil
// bl (Mongo off) → returns at once, nothing spins, feed never fetched.
// Best-effort: a failed fetch/write logs + retries next tick.
func RunIPsumSync(ctx context.Context, bl *BlockList) {
	if bl == nil {
		log.Printf("ipsum blocklist: disabled (no Mongo); skipping periodic sync")
		return
	}

	syncOnce := func() {
		c, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		switch res, err := SyncIPsum(c, bl); {
		case err != nil:
			log.Printf("ipsum blocklist: sync failed: %v", err)
		case res.Skipped:
			log.Printf("ipsum blocklist: corpus fresh (last synced %s), skipped download", res.LastSync.Format(time.RFC3339))
		default:
			log.Printf("ipsum blocklist: synced %d IPs (%d written)", res.Parsed, res.Written)
		}
	}

	syncOnce()
	ticker := time.NewTicker(ipsumRefreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce()
		}
	}
}

// fetchIPsum GETs the feed body. Caller closes it. Non-200 = error (body
// drained + closed) → a GitHub outage/redirect never parses as an empty feed +
// wipes nothing; SyncIPsum retries next tick.
func fetchIPsum(ctx context.Context) (io.ReadCloser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ipsumURL, nil)
	if err != nil {
		return nil, err
	}
	resp, err := ipsumHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		return nil, fmt.Errorf("fetch ipsum feed: unexpected status %s", resp.Status)
	}
	return resp.Body, nil
}

// parseIPsum turns the feed body into entries. Pure (no Mongo, no network) →
// unit-testable offline. Comment lines skipped except "# Last update:" (stamp
// captured). A line that isn't `<valid-ip> <count>` is skipped, not fatal —
// one stray row mustn't abort a 45k-line sync.
func parseIPsum(r io.Reader) ([]BlockEntry, time.Time, error) {
	var (
		entries  []BlockEntry
		feedTime time.Time
	)
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			if t, ok := parseIPsumHeaderTime(line); ok {
				feedTime = t
			}
			continue
		}
		ip, count, ok := parseIPsumLine(line)
		if !ok {
			continue
		}
		entries = append(entries, ipsumEntry(ip, count, feedTime))
	}
	if err := sc.Err(); err != nil {
		return nil, time.Time{}, err
	}
	return entries, feedTime, nil
}

// parseIPsumLine reads one `IP<TAB>count` row. ok=false unless a valid IP + a
// non-negative int.
func parseIPsumLine(line string) (ip string, count int, ok bool) {
	fields := strings.Fields(line) // tab-separated in practice; Fields tolerates any space run
	if len(fields) < 2 {
		return "", 0, false
	}
	if net.ParseIP(fields[0]) == nil {
		return "", 0, false
	}
	n, err := strconv.Atoi(fields[1])
	if err != nil || n < 0 {
		return "", 0, false
	}
	return fields[0], n, true
}

// parseIPsumHeaderTime pulls the stamp from
// "# Last update: Tue, 21 Jul 2026 03:00:58 +0200" (RFC 1123, numeric zone).
// ok=false for any other comment line.
func parseIPsumHeaderTime(line string) (time.Time, bool) {
	const marker = "Last update:"
	i := strings.Index(line, marker)
	if i < 0 {
		return time.Time{}, false
	}
	v := strings.TrimSpace(line[i+len(marker):])
	if t, err := time.Parse(time.RFC1123Z, v); err == nil {
		return t, true
	}
	return time.Time{}, false
}

// ipsumEntry builds the record for one listed IP, stashing all ipsum exposes:
// count as Count, feed stamp + URL in Meta → nothing dropped.
func ipsumEntry(ip string, count int, feedTime time.Time) BlockEntry {
	meta := map[string]any{"feed_url": ipsumURL}
	if !feedTime.IsZero() {
		meta["feed_updated_at"] = feedTime
	}
	return BlockEntry{
		IP:     ip,
		Source: BlocklistSourceIPsum,
		Count:  count,
		Reason: fmt.Sprintf("Listed on %d threat-intelligence blocklist(s) (IPsum aggregate feed)", count),
		Meta:   meta,
	}
}
