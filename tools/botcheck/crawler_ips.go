package botcheck

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"
)

var crawlerFeeds = [...]struct{ op, url string }{
	{"google", "https://developers.google.com/static/crawling/ipranges/common-crawlers.json"},
	{"bing", "https://www.bing.com/toolbox/bingbot.json"},
	{"openai", "https://openai.com/gptbot.json"},
}

type crawlerPrefixList struct {
	Prefixes []struct {
		IPv4Prefix string `json:"ipv4Prefix"`
		IPv6Prefix string `json:"ipv6Prefix"`
	} `json:"prefixes"`
}

var (
	crawlerHTTPClient = &http.Client{Timeout: 30 * time.Second}
	crawlerIndex      atomic.Pointer[map[string][]netip.Prefix]
)

func init() {
	empty := make(map[string][]netip.Prefix)
	crawlerIndex.Store(&empty)
}

func storeCrawlerPrefixes(operator string, prefixes []netip.Prefix) {
	newMap := make(map[string][]netip.Prefix)
	if curr := crawlerIndex.Load(); curr != nil {
		newMap = maps.Clone(*curr)
	}
	newMap[operator] = prefixes
	crawlerIndex.Store(&newMap)
}

// MatchCrawlerIP checks if an IP belongs to the official published IP ranges of an operator.
func MatchCrawlerIP(operator, ipStr string) bool {
	idx := crawlerIndex.Load()
	if idx == nil {
		return false
	}
	prefixes := (*idx)[operator]
	if len(prefixes) == 0 {
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

// RunCrawlerSync syncs official crawler IP feeds periodically until ctx is canceled.
func RunCrawlerSync(ctx context.Context) {
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
}

func syncAllCrawlerFeeds(ctx context.Context) {
	for _, feed := range crawlerFeeds {
		if ctx.Err() != nil {
			return
		}
		prefixes := fetchCrawlerFeed(ctx, crawlerHTTPClient, feed.url)
		if len(prefixes) > 0 {
			storeCrawlerPrefixes(feed.op, prefixes)
			log.Printf("[botcheck.crawler] synced %d prefixes for %s", len(prefixes), feed.op)
		}
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

	var data crawlerPrefixList
	if err := json.NewDecoder(io.LimitReader(resp.Body, 5<<20)).Decode(&data); err != nil {
		return nil
	}

	var prefixes []netip.Prefix
	for _, item := range data.Prefixes {
		for _, raw := range [...]string{item.IPv4Prefix, item.IPv6Prefix} {
			if raw != "" {
				if p, err := netip.ParsePrefix(raw); err == nil {
					prefixes = append(prefixes, p)
				}
			}
		}
	}
	return prefixes
}

// SeedCrawlerPrefixesForTest populates prefixes for an operator in unit tests.
func SeedCrawlerPrefixesForTest(operator string, rawPrefixes []string) {
	var list []netip.Prefix
	for _, s := range rawPrefixes {
		if p, err := netip.ParsePrefix(s); err == nil {
			list = append(list, p)
		}
	}
	storeCrawlerPrefixes(operator, list)
}
