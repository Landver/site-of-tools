package mailtools

import (
	"bufio"
	"context"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

var (
	canonicalDisposableURL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
)

// StartSyncWorker initiates the daily background worker to sync datasets.
func StartSyncWorker(ctx context.Context, store *Store, interval time.Duration) {
	if interval <= 0 {
		interval = 24 * time.Hour
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Run initial check after a short boot delay (e.g. 1 minute)
		bootTimer := time.NewTimer(1 * time.Minute)
		select {
		case <-ctx.Done():
			bootTimer.Stop()
			return
		case <-bootTimer.C:
			syncDisposableDomains(ctx, store)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				syncDisposableDomains(ctx, store)
			}
		}
	}()
}

func syncDisposableDomains(ctx context.Context, store *Store) {
	current := ActiveClassifier()
	client := &http.Client{Timeout: 30 * time.Second}

	req, err := http.NewRequestWithContext(ctx, "GET", canonicalDisposableURL, nil)
	if err != nil {
		log.Printf("[mailtools.worker] failed to create sync request: %v", err)
		return
	}

	// Fetch sync meta from MongoDB if available
	var lastMeta *SyncMeta
	if store != nil {
		lastMeta, _ = store.GetSyncMeta(ctx, "disposable")
		if lastMeta != nil && lastMeta.Hash != "" {
			req.Header.Set("If-None-Match", lastMeta.Hash)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[mailtools.worker] sync request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		// No changes upstream
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Printf("[mailtools.worker] sync returned HTTP %d", resp.StatusCode)
		return
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 10*1024*1024))
	var validDomains []string
	for scanner.Scan() {
		l := strings.TrimSpace(scanner.Text())
		if l != "" && !strings.HasPrefix(l, "#") {
			validDomains = append(validDomains, l)
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("[mailtools.worker] failed reading response stream: %v", err)
		return
	}

	// Whitelist Shield & Sanity Checks:
	// 1. Must contain at least 5,000 domains.
	if len(validDomains) < 5000 {
		log.Printf("[mailtools.worker] rejected update: only %d domains (expected >= 5000)", len(validDomains))
		return
	}

	// 2. Whitelist Shield: sanitize and strip whitelisted domains from disposable blocklist
	sanitized := make([]string, 0, len(validDomains))
	for _, d := range validDomains {
		if current.IsWhitelisted(d) {
			log.Printf("[mailtools.worker] skipped whitelisted domain from update: %s", d)
			continue
		}
		sanitized = append(sanitized, d)
	}
	validDomains = sanitized

	// Prevent cold-boot clobbering
	if len(current.FreemailDomains()) == 0 || len(current.WhitelistDomains()) == 0 {
		_ = InitFromEmbedded()
		current = ActiveClassifier()
	}

	// Atomic hot-swap with preserved freemail, wildcards and whitelists
	newClassifier := NewDomainClassifier(
		validDomains,
		current.WildcardPatterns(),
		current.FreemailDomains(),
		current.WhitelistDomains(),
	)
	SetGlobalClassifier(newClassifier)

	etag := resp.Header.Get("ETag")
	if store != nil {
		_ = store.SetSyncMeta(ctx, SyncMeta{
			Key:       "disposable",
			Hash:      etag,
			Count:     len(validDomains),
			UpdatedAt: time.Now().UTC(),
		})
	}
	log.Printf("[mailtools.worker] successfully synced %d disposable domains (ETag: %s)", len(validDomains), etag)
}
