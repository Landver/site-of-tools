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
	burnerEmailURL         = "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"
	// A short download is a truncated or hijacked list; the canonical one holds over 5,000 domains.
	minDisposableDomains = 5000
	syncInterval         = 24 * time.Hour
)

// StartSyncWorker refreshes the disposable list a minute after boot, then daily.
func StartSyncWorker(ctx context.Context) {
	go func() {
		wait := time.NewTimer(time.Minute)
		defer wait.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-wait.C:
				syncDisposableDomains(ctx)
				wait.Reset(syncInterval)
			}
		}
	}()
}

func syncDisposableDomains(ctx context.Context) {
	client := &http.Client{Timeout: 30 * time.Second}
	domainMap := make(map[string]struct{})

	// 1. Fetch canonical disposable list
	if lines := fetchDomainList(ctx, client, canonicalDisposableURL); len(lines) > 0 {
		for _, d := range lines {
			domainMap[cleanDomain(d)] = struct{}{}
		}
	}

	// 2. Fetch extended burner email list
	if lines := fetchDomainList(ctx, client, burnerEmailURL); len(lines) > 0 {
		for _, d := range lines {
			domainMap[cleanDomain(d)] = struct{}{}
		}
	}

	if len(domainMap) < minDisposableDomains {
		log.Printf("[mailtools.worker] rejected update: only %d domains (expected >= %d)", len(domainMap), minDisposableDomains)
		return
	}

	domains := make([]string, 0, len(domainMap))
	for d := range domainMap {
		domains = append(domains, d)
	}
	synced.Store(classifierWith(domains))
	log.Printf("[mailtools.worker] synced %d aggregated disposable domains", len(domains))
}

func fetchDomainList(ctx context.Context, client *http.Client, targetURL string) []string {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		log.Printf("[mailtools.worker] failed to create sync request for %s: %v", targetURL, err)
		return nil
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[mailtools.worker] sync request failed for %s: %v", targetURL, err)
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		log.Printf("[mailtools.worker] sync returned HTTP %d for %s", resp.StatusCode, targetURL)
		return nil
	}
	return readLines(io.LimitReader(resp.Body, 15<<20))
}
