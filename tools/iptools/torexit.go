package iptools

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"
)

const (
	torExitURL         = "https://check.torproject.org/torbulkexitlist"
	torExitHTTPTimeout = 30 * time.Second
	torExitUpsertChunk = 5000
)

var torExitHTTPClient = &http.Client{Timeout: torExitHTTPTimeout}

// SyncTorExit fetches the current Tor bulk exit node list and upserts it into the shared blocklist.
func SyncTorExit(ctx context.Context, bl *BlockList) (BlockSyncResult, error) {
	return bl.syncFeed(ctx, BlocklistSourceTorExit, torExitUpsertChunk,
		func(ctx context.Context) (io.ReadCloser, error) {
			return fetchFeed(ctx, torExitHTTPClient, torExitURL, "tor exit list")
		},
		func(r io.Reader) ([]BlockEntry, error) {
			return ParseTorExitList(r)
		},
	)
}

// RunTorExitSync runs an immediate sync and then keeps the Tor exit list updated daily.
func RunTorExitSync(ctx context.Context, bl *BlockList) {
	runDailySync(ctx, bl, "tor-exit", "IPs", SyncTorExit)
}

// ParseTorExitList parses an IP-per-line Tor bulk exit node list.
func ParseTorExitList(r io.Reader) ([]BlockEntry, error) {
	var entries []BlockEntry
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		addr, err := netip.ParseAddr(line)
		if err != nil {
			continue
		}
		entries = append(entries, BlockEntry{
			IP:     addr.Unmap().String(),
			Source: BlocklistSourceTorExit,
			Reason: "tor exit node",
		})
	}
	return entries, sc.Err()
}
