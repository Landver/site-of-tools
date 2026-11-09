package iptools

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const (
	rpkiCloudflareURL = "https://rpki.cloudflare.com/rpki.json"
	rpkiSyncInterval  = 24 * time.Hour
)

// RPKIValidation represents RFC 6811 Route Origin Validation status.
type RPKIValidation struct {
	Status    string `json:"status"` // "valid", "invalid", "not_found"
	ROAPrefix string `json:"roa_prefix,omitempty"`
	ROAASN    uint32 `json:"roa_asn,omitempty"`
	MaxLength int    `json:"max_length,omitempty"`
	Details   string `json:"details,omitempty"`
}

type roaEntry struct {
	prefix    netip.Prefix
	asn       uint32
	maxLength int
}

type rawROA struct {
	ASN       any    `json:"asn"` // can be string or uint32 in various feeds
	Prefix    string `json:"prefix"`
	MaxLength int    `json:"maxLength"`
}

type rawRPKIResponse struct {
	ROAs []rawROA `json:"roas"`
}

// RPKIIndex provides in-memory Longest Prefix Match (LPM) for RPKI ROAs.
type RPKIIndex struct {
	v4List []roaEntry
	v6List []roaEntry
}

var activeRPKI atomic.Pointer[RPKIIndex]

func init() {
	activeRPKI.Store(&RPKIIndex{})
}

// ValidateRPKI checks an announced prefix or IP and origin ASN against active ROAs.
func ValidateRPKI(ipStr, asnStr string) RPKIValidation {
	idx := activeRPKI.Load()
	if idx == nil || (len(idx.v4List) == 0 && len(idx.v6List) == 0) {
		return RPKIValidation{Status: "not_found", Details: "RPKI ROA database not loaded"}
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return RPKIValidation{Status: "not_found", Details: "invalid target IP"}
	}

	cleanASN := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(asnStr), "AS"), "as")
	originASN64, _ := strconv.ParseUint(cleanASN, 10, 32)
	originASN := uint32(originASN64)

	var list []roaEntry
	if addr.Is4() {
		list = idx.v4List
	} else {
		list = idx.v6List
	}

	var bestCover *roaEntry
	// Find longest covering prefix
	for i := range list {
		entry := &list[i]
		if entry.prefix.Contains(addr) {
			if bestCover == nil || entry.prefix.Bits() > bestCover.prefix.Bits() {
				bestCover = entry
			}
		}
	}

	if bestCover == nil {
		return RPKIValidation{
			Status:  "not_found",
			Details: "No covering ROA found in global RPKI repository",
		}
	}

	// Covering ROA found. Check RFC 6811 rules
	targetBits := bestCover.prefix.Bits()
	if bestCover.asn == originASN && targetBits <= bestCover.maxLength {
		return RPKIValidation{
			Status:    "valid",
			ROAPrefix: bestCover.prefix.String(),
			ROAASN:    bestCover.asn,
			MaxLength: bestCover.maxLength,
			Details:   "Valid: announced route matches authentic cryptographically signed ROA",
		}
	}

	// Invalid reason
	if bestCover.asn != originASN {
		return RPKIValidation{
			Status:    "invalid",
			ROAPrefix: bestCover.prefix.String(),
			ROAASN:    bestCover.asn,
			MaxLength: bestCover.maxLength,
			Details:   "Invalid (AS Mismatch): prefix is authorized for AS" + strconv.FormatUint(uint64(bestCover.asn), 10) + ", but announced by AS" + strconv.FormatUint(uint64(originASN), 10),
		}
	}

	return RPKIValidation{
		Status:    "invalid",
		ROAPrefix: bestCover.prefix.String(),
		ROAASN:    bestCover.asn,
		MaxLength: bestCover.maxLength,
		Details:   "Invalid (MaxLength Exceeded): prefix length exceeds ROA maxLength " + strconv.Itoa(bestCover.maxLength),
	}
}

// StartRPKISyncWorker syncs Cloudflare RPKI JSON periodically in the background.
func StartRPKISyncWorker(ctx context.Context) {
	go func() {
		// Run initial sync after 5 seconds, then daily
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				syncRPKI(ctx)
				timer.Reset(rpkiSyncInterval)
			}
		}
	}()
}

func syncRPKI(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rpkiCloudflareURL, nil)
	if err != nil {
		log.Printf("[iptools.rpki] failed to build request: %v", err)
		return
	}
	req.Header.Set("User-Agent", "corpberry-iptools/1.0 (+https://ip.corpberry.com)")
	req.Header.Set("Accept-Encoding", "gzip")

	client := &http.Client{Timeout: 90 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("[iptools.rpki] sync request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[iptools.rpki] sync returned HTTP %d", resp.StatusCode)
		return
	}

	var reader io.Reader = resp.Body
	if resp.Header.Get("Content-Encoding") == "gzip" {
		gz, err := gzip.NewReader(resp.Body)
		if err != nil {
			log.Printf("[iptools.rpki] gzip open failed: %v", err)
			return
		}
		defer gz.Close()
		reader = gz
	}

	var data rawRPKIResponse
	// Stream JSON with limit of 250MB uncompressed
	if err := json.NewDecoder(io.LimitReader(reader, 250<<20)).Decode(&data); err != nil {
		log.Printf("[iptools.rpki] JSON parse error: %v", err)
		return
	}

	if len(data.ROAs) < 100000 {
		log.Printf("[iptools.rpki] incomplete feed: only %d ROAs", len(data.ROAs))
		return
	}

	var v4, v6 []roaEntry
	for _, r := range data.ROAs {
		p, err := netip.ParsePrefix(r.Prefix)
		if err != nil {
			continue
		}
		var asn uint32
		switch v := r.ASN.(type) {
		case float64:
			asn = uint32(v)
		case string:
			clean := strings.TrimPrefix(strings.TrimPrefix(v, "AS"), "as")
			n, _ := strconv.ParseUint(clean, 10, 32)
			asn = uint32(n)
		}
		if asn == 0 {
			continue
		}
		maxL := r.MaxLength
		if maxL < p.Bits() {
			maxL = p.Bits()
		}
		entry := roaEntry{prefix: p, asn: asn, maxLength: maxL}
		if p.Addr().Is4() {
			v4 = append(v4, entry)
		} else {
			v6 = append(v6, entry)
		}
	}

	activeRPKI.Store(&RPKIIndex{v4List: v4, v6List: v6})
	log.Printf("[iptools.rpki] synced %d IPv4 and %d IPv6 ROAs", len(v4), len(v6))
}

// TestROA is exported for unit testing SeedRPKIForTest.
type TestROA struct {
	Prefix    netip.Prefix
	ASN       uint32
	MaxLength int
}

// SeedRPKIForTest populates test ROAs.
func SeedRPKIForTest(roas []TestROA) {
	var v4, v6 []roaEntry
	for _, r := range roas {
		entry := roaEntry{prefix: r.Prefix, asn: r.ASN, maxLength: r.MaxLength}
		if r.Prefix.Addr().Is4() {
			v4 = append(v4, entry)
		} else {
			v6 = append(v6, entry)
		}
	}
	activeRPKI.Store(&RPKIIndex{v4List: v4, v6List: v6})
}
