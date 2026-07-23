package iptools

import (
	"bufio"
	"context"
	"fmt"
	"io"
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
// ban. Shared sync/fetch scaffolding (BlockSyncResult, syncFeed, fetchFeed,
// runDailySync) lives in blocklist.go, reused by spamhaus.go's identical shape.

const (
	// ipsumURL: raw aggregate feed. count column = ipsum's finest published
	// granularity (no per-feed attribution) → count is the most we preserve
	// per IP.
	ipsumURL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

	// ipsumHTTPTimeout bounds the download; feed ~1.8 MB.
	ipsumHTTPTimeout = 60 * time.Second

	// ipsumUpsertChunk bounds entries per BulkWrite → a ~45k-line feed doesn't
	// build one giant command or hold every write model at once.
	ipsumUpsertChunk = 5000
)

// ipsumHTTPClient dedicated (not http.DefaultClient) → the timeout is ours,
// not mutable by other code sharing the default.
var ipsumHTTPClient = &http.Client{Timeout: ipsumHTTPTimeout}

// SyncIPsum downloads the ipsum feed + upserts every listed IP under source
// "ipsum" — a thin wrapper supplying ipsum's fetch/parse to BlockList.syncFeed
// (blocklist.go), which owns the shared skip/nil/chunking/partial-write
// behavior every feed sync shares.
func SyncIPsum(ctx context.Context, bl *BlockList) (BlockSyncResult, error) {
	return bl.syncFeed(ctx, BlocklistSourceIPsum, ipsumUpsertChunk,
		func(ctx context.Context) (io.ReadCloser, error) {
			return fetchFeed(ctx, ipsumHTTPClient, ipsumURL, "ipsum feed")
		},
		func(r io.Reader) ([]BlockEntry, error) {
			entries, _, err := parseIPsum(r) // feed timestamp already folded into each entry's Meta
			return entries, err
		},
	)
}

// RunIPsumSync runs SyncIPsum once now (self-skips if fresh), then on a daily
// ticker until ctx is cancelled — a thin wrapper over the shared runDailySync
// (blocklist.go). Launch as a background goroutine from main.
func RunIPsumSync(ctx context.Context, bl *BlockList) {
	runDailySync(ctx, bl, "ipsum", "IPs", SyncIPsum)
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
