package botcheck

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

// CrawlerFeed defines an official crawler IP list source.
type CrawlerFeed struct {
	Operator string // "google", "bing", "openai"
	URL      string
}

var crawlerFeeds = []CrawlerFeed{
	{Operator: "google", URL: "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"},
	{Operator: "bing", URL: "https://www.bing.com/toolbox/bingbot.json"},
	{Operator: "openai", URL: "https://openai.com/gptbot.json"},
}

type prefixItem struct {
	IPv4Prefix string `json:"ipv4Prefix"`
	IPv6Prefix string `json:"ipv6Prefix"`
}

type crawlerPrefixList struct {
	Prefixes []prefixItem `json:"prefixes"`
}

// CrawlerPrefixIndex is an atomic, immutable lookup table of verified IP prefixes.
type CrawlerPrefixIndex struct {
	prefixes map[string][]netip.Prefix // operator -> prefixes
}

var crawlerIndex atomic.Pointer[CrawlerPrefixIndex]

func init() {
	crawlerIndex.Store(&CrawlerPrefixIndex{prefixes: make(map[string][]netip.Prefix)})
}

// MatchCrawlerIP checks if an IP belongs to the official published IP ranges of an operator.
func MatchCrawlerIP(operator, ipStr string) bool {
	idx := crawlerIndex.Load()
	if idx == nil {
		return false
	}
	prefixes, ok := idx.prefixes[operator]
	if !ok || len(prefixes) == 0 {
		return false
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// SeedCrawlerPrefixesForTest populates prefixes for an operator in unit tests.
func SeedCrawlerPrefixesForTest(operator string, rawPrefixes []string) {
	curr := crawlerIndex.Load()
	newMap := make(map[string][]netip.Prefix)
	if curr != nil {
		for k, v := range curr.prefixes {
			newMap[k] = v
		}
	}
	var list []netip.Prefix
	for _, s := range rawPrefixes {
		if p, err := netip.ParsePrefix(s); err == nil {
			list = append(list, p)
		}
	}
	newMap[operator] = list
	crawlerIndex.Store(&CrawlerPrefixIndex{prefixes: newMap})
}

// StartCrawlerSyncWorker syncs official crawler IP feeds periodically.
func StartCrawlerSyncWorker(ctx context.Context) {
	go func() {
		// Sync after 10 seconds, then daily
		timer := time.NewTimer(10 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				syncAllCrawlerFeeds(ctx)
				timer.Reset(24 * time.Hour)
			}
		}
	}()
}

func syncAllCrawlerFeeds(ctx context.Context) {
	client := &http.Client{Timeout: 30 * time.Second}
	newMap := make(map[string][]netip.Prefix)

	for _, feed := range crawlerFeeds {
		prefixes := fetchCrawlerFeed(ctx, client, feed.URL)
		if len(prefixes) > 0 {
			newMap[feed.Operator] = prefixes
			log.Printf("[botcheck.crawler] synced %d prefixes for %s", len(prefixes), feed.Operator)
		}
	}

	if len(newMap) > 0 {
		// Merge with existing ones if any feed failed
		if curr := crawlerIndex.Load(); curr != nil {
			for op, existing := range curr.prefixes {
				if _, ok := newMap[op]; !ok {
					newMap[op] = existing
				}
			}
		}
		crawlerIndex.Store(&CrawlerPrefixIndex{prefixes: newMap})
	}
}

func fetchCrawlerFeed(ctx context.Context, client *http.Client, feedURL string) []netip.Prefix {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, feedURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "corpberry-botcheck/1.0 (+https://botcheck.corpberry.com)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	if err != nil {
		return nil
	}

	var data crawlerPrefixList
	if err := json.Unmarshal(body, &data); err != nil {
		return nil
	}

	var prefixes []netip.Prefix
	for _, item := range data.Prefixes {
		raw := item.IPv4Prefix
		if raw == "" {
			raw = item.IPv6Prefix
		}
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			prefixes = append(prefixes, p)
		}
	}
	return prefixes
}
