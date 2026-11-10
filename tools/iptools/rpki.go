package iptools

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
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

// ROAEntry holds an authorized prefix route origin assertion.
type ROAEntry struct {
	Prefix    netip.Prefix
	ASN       uint32
	MaxLength int
}

type rawRPKIResponse struct {
	ROAs []struct {
		ASN       any    `json:"asn"`
		Prefix    string `json:"prefix"`
		MaxLength int    `json:"maxLength"`
	} `json:"roas"`
}

// RPKIIndex provides 256-bucket fast IPv4 lookups + IPv6 list.
type RPKIIndex struct {
	v4Buckets [256][]ROAEntry
	v6List    []ROAEntry
}

var (
	activeRPKI     atomic.Pointer[RPKIIndex]
	rpkiHTTPClient = &http.Client{Timeout: 90 * time.Second}
)

// ValidateRPKI checks an IP and origin ASN against active ROAs per RFC 6811.
// Returns nil if the database is uninitialized or IP/ASN is invalid.
func ValidateRPKI(ipStr, asnStr string) *RPKIValidation {
	idx := activeRPKI.Load()
	if idx == nil {
		return nil
	}

	addr, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return nil
	}

	originASN, err := ParseASN(asnStr)
	if err != nil {
		return nil
	}

	var list []ROAEntry
	if addr.Is4() {
		list = idx.v4Buckets[addr.As4()[0]]
	} else {
		list = idx.v6List
	}
	if len(list) == 0 {
		return &RPKIValidation{Status: "not_found", Details: "No covering ROA found in global RPKI repository"}
	}

	// RFC 6811: Valid if at least ONE covering ROA matches origin ASN.
	// Longest covering prefix is recorded for attribution.
	var (
		validROA   *ROAEntry
		invalidROA *ROAEntry
	)
	for i := range list {
		entry := &list[i]
		if !entry.Prefix.Contains(addr) {
			continue
		}
		if entry.ASN == originASN {
			if validROA == nil || entry.Prefix.Bits() > validROA.Prefix.Bits() {
				validROA = entry
			}
		} else if invalidROA == nil || entry.Prefix.Bits() > invalidROA.Prefix.Bits() {
			invalidROA = entry
		}
	}

	if validROA != nil {
		return &RPKIValidation{
			Status:    "valid",
			ROAPrefix: validROA.Prefix.String(),
			ROAASN:    validROA.ASN,
			MaxLength: validROA.MaxLength,
			Details:   "Valid: route matches authentic cryptographically signed ROA",
		}
	}
	if invalidROA != nil {
		return &RPKIValidation{
			Status:    "invalid",
			ROAPrefix: invalidROA.Prefix.String(),
			ROAASN:    invalidROA.ASN,
			MaxLength: invalidROA.MaxLength,
			Details:   fmt.Sprintf("Invalid (AS Mismatch): prefix authorized for AS%d, but announced by AS%d", invalidROA.ASN, originASN),
		}
	}
	return &RPKIValidation{Status: "not_found", Details: "No covering ROA found in global RPKI repository"}
}

// RunRPKISync syncs Cloudflare RPKI JSON periodically until ctx cancels.
func RunRPKISync(ctx context.Context) {
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
}

func syncRPKI(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rpkiCloudflareURL, nil)
	if err != nil {
		log.Printf("[iptools.rpki] request error: %v", err)
		return
	}
	req.Header.Set("User-Agent", iptoolsUserAgent)

	resp, err := rpkiHTTPClient.Do(req)
	if err != nil {
		log.Printf("[iptools.rpki] sync request failed: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Printf("[iptools.rpki] sync returned HTTP %d", resp.StatusCode)
		return
	}

	var data rawRPKIResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 250<<20)).Decode(&data); err != nil {
		log.Printf("[iptools.rpki] JSON parse error: %v", err)
		return
	}

	if len(data.ROAs) < 100000 {
		log.Printf("[iptools.rpki] incomplete feed: only %d ROAs", len(data.ROAs))
		return
	}

	idx := &RPKIIndex{}
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
			parsed, err := ParseASN(v)
			if err == nil {
				asn = parsed
			}
		}
		if asn == 0 {
			continue
		}
		maxL := r.MaxLength
		if maxL < p.Bits() {
			maxL = p.Bits()
		}
		entry := ROAEntry{Prefix: p, ASN: asn, MaxLength: maxL}
		if p.Addr().Is4() {
			idx.v4Buckets[p.Addr().As4()[0]] = append(idx.v4Buckets[p.Addr().As4()[0]], entry)
		} else {
			idx.v6List = append(idx.v6List, entry)
		}
	}

	activeRPKI.Store(idx)
	log.Printf("[iptools.rpki] synced %d total ROAs", len(data.ROAs))
}

// SeedRPKIForTest populates test ROAs.
func SeedRPKIForTest(roas []ROAEntry) {
	idx := &RPKIIndex{}
	for _, r := range roas {
		if r.Prefix.Addr().Is4() {
			idx.v4Buckets[r.Prefix.Addr().As4()[0]] = append(idx.v4Buckets[r.Prefix.Addr().As4()[0]], r)
		} else {
			idx.v6List = append(idx.v6List, r)
		}
	}
	activeRPKI.Store(idx)
}
