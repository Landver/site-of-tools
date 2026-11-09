package mailtools

import (
	"context"
	"io"
	"log"
	"maps"
	"net/http"
	"slices"
	"time"
)

const (
	canonicalDisposableURL = "https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/master/disposable_email_blocklist.conf"
	burnerEmailURL         = "https://raw.githubusercontent.com/wesbos/burner-email-providers/master/emails.txt"
	minDisposableDomains   = 5000
	syncInterval           = 24 * time.Hour
)

// RunSync refreshes the disposable list a minute after boot, then daily until ctx cancels.
func RunSync(ctx context.Context) {
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
}

// StartSyncWorker is a non-blocking helper for background execution.
func StartSyncWorker(ctx context.Context) {
	go RunSync(ctx)
}

func syncDisposableDomains(ctx context.Context) {
	client := &http.Client{Timeout: 30 * time.Second}
	domainMap := make(map[string]struct{})

	for _, u := range [...]string{canonicalDisposableURL, burnerEmailURL} {
		if ctx.Err() != nil {
			return
		}
		for _, d := range fetchDomainList(ctx, client, u) {
			if d = cleanDomain(d); d != "" {
				domainMap[d] = struct{}{}
			}
		}
	}

	if len(domainMap) < minDisposableDomains {
		log.Printf("[mailtools.worker] rejected update: only %d domains (expected >= %d)", len(domainMap), minDisposableDomains)
		return
	}

	domains := slices.Collect(maps.Keys(domainMap))
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
