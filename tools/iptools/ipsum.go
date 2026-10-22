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

// stamparm/ipsum folds 30+ public blocklists into `IP<TAB>count` (lists flagging it); Unlicense.

const (
	// count is ipsum's finest granularity: it publishes no per-list attribution.
	ipsumURL = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"

	ipsumHTTPTimeout = 60 * time.Second

	// Chunked so the ~45k-line feed never builds one giant BulkWrite.
	ipsumUpsertChunk = 5000
)

// Own client so no code sharing http.DefaultClient can change its timeout.
var ipsumHTTPClient = &http.Client{Timeout: ipsumHTTPTimeout}

func SyncIPsum(ctx context.Context, bl *BlockList) (BlockSyncResult, error) {
	return bl.syncFeed(ctx, BlocklistSourceIPsum, ipsumUpsertChunk,
		func(ctx context.Context) (io.ReadCloser, error) {
			return fetchFeed(ctx, ipsumHTTPClient, ipsumURL, "ipsum feed")
		},
		func(r io.Reader) ([]BlockEntry, error) {
			entries, _, err := parseIPsum(r) // feed time is already in each entry's Meta
			return entries, err
		},
	)
}

// RunIPsumSync syncs now, then daily until ctx ends; run it as a goroutine from main.
func RunIPsumSync(ctx context.Context, bl *BlockList) {
	runDailySync(ctx, bl, "ipsum", "IPs", SyncIPsum)
}

// A malformed line is skipped, not fatal: one stray row mustn't abort a 45k-line sync.
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

// parseIPsumHeaderTime reads "# Last update: Tue, 21 Jul 2026 03:00:58 +0200" (RFC 1123Z).
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
