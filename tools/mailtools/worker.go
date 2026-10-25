package mailtools

import (
	"context"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	canonicalDisposableURL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
	// A short download is a truncated or hijacked list; the canonical one holds over 5,000 domains.
	minDisposableDomains = 5000
)

// StartSyncWorker refreshes the disposable list a minute after boot, then every interval (default a day).
func StartSyncWorker(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}
	go func() {
		wait := time.NewTimer(time.Minute)
		defer wait.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wait.C:
				syncDisposableDomains(ctx)
				wait.Reset(interval)
			}
		}
	}()
}

func syncDisposableDomains(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, canonicalDisposableURL, nil)
	if err != nil {
		log.Printf("[mailtools.worker] failed to create sync request: %v", err)
		return
	}
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		log.Printf("[mailtools.worker] sync request failed: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[mailtools.worker] sync returned HTTP %d", resp.StatusCode)
		return
	}

	domains := readLines(io.LimitReader(resp.Body, 10<<20))
	if len(domains) < minDisposableDomains {
		log.Printf("[mailtools.worker] rejected update: only %d domains (expected >= %d)", len(domains), minDisposableDomains)
		return
	}
	active.Store(classifierWith(domains))
	log.Printf("[mailtools.worker] synced %d disposable domains", len(domains))
}
