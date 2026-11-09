package iptools

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// PeeringInfo summarizes an autonomous system's connectivity profile from PeeringDB.
type PeeringInfo struct {
	ASN      uint32   `json:"asn"`
	Name     string   `json:"name,omitempty"`
	Policy   string   `json:"policy,omitempty"`    // Open, Selective, Restrictive, etc.
	Traffic  string   `json:"traffic,omitempty"`   // e.g. "100-500Gbps"
	Ratio    string   `json:"ratio,omitempty"`     // Balanced, Mostly Inbound, Mostly Outbound
	Scope    string   `json:"scope,omitempty"`     // Regional, Global, etc.
	IXPCount int      `json:"ixp_count,omitempty"` // Total IXPs connected
	IXPs     []string `json:"ixps,omitempty"`      // Sample of IXP exchange names
	Website  string   `json:"website,omitempty"`
}

type peeringDBDump struct {
	Net struct {
		Data []struct {
			ASN     uint32 `json:"asn"`
			Name    string `json:"name"`
			Policy  string `json:"policy_general"`
			Traffic string `json:"info_traffic"`
			Ratio   string `json:"info_ratio"`
			Scope   string `json:"info_scope"`
			Website string `json:"website"`
			ID      int    `json:"id"`
		} `json:"data"`
	} `json:"net"`
	NetIXLAN struct {
		Data []struct {
			NetID  int    `json:"net_id"`
			IXName string `json:"name"`
		} `json:"data"`
	} `json:"netixlan"`
}

var (
	peeringCache      atomic.Pointer[map[uint32]*PeeringInfo]
	peeringHTTPClient = &http.Client{Timeout: 90 * time.Second}
)

const peeringDBDumpURL = "https://public.peeringdb.com/export/peeringdb_dump_latest.json"

// LookupPeering returns PeeringDB network & IXP details for an ASN string (e.g. "15169" or "AS15169").
func LookupPeering(asnStr string) *PeeringInfo {
	cache := peeringCache.Load()
	if cache == nil {
		return nil
	}
	clean := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(asnStr), "AS"), "as")
	asn64, err := strconv.ParseUint(clean, 10, 32)
	if err != nil || asn64 == 0 {
		return nil
	}
	return (*cache)[uint32(asn64)]
}

// SetPeeringCacheForTest injects test data into the atomic pointer.
func SetPeeringCacheForTest(m map[uint32]*PeeringInfo) {
	peeringCache.Store(&m)
}

// ParsePeeringDBDump parses a PeeringDB export JSON stream into the ASN map.
func ParsePeeringDBDump(r io.Reader) (map[uint32]*PeeringInfo, error) {
	var dump peeringDBDump
	if err := json.NewDecoder(r).Decode(&dump); err != nil {
		return nil, err
	}

	netIDToASN := make(map[int]uint32, len(dump.Net.Data))
	result := make(map[uint32]*PeeringInfo, len(dump.Net.Data))

	for _, n := range dump.Net.Data {
		if n.ASN == 0 {
			continue
		}
		info := &PeeringInfo{
			ASN:     n.ASN,
			Name:    n.Name,
			Policy:  n.Policy,
			Traffic: n.Traffic,
			Ratio:   n.Ratio,
			Scope:   n.Scope,
			Website: n.Website,
		}
		result[n.ASN] = info
		netIDToASN[n.ID] = n.ASN
	}

	for _, ix := range dump.NetIXLAN.Data {
		asn, ok := netIDToASN[ix.NetID]
		if !ok {
			continue
		}
		info := result[asn]
		info.IXPCount++
		if len(info.IXPs) < 10 && ix.IXName != "" {
			info.IXPs = append(info.IXPs, ix.IXName)
		}
	}

	return result, nil
}

// RunPeeringDBSync runs weekly PeeringDB snapshot downloads.
func RunPeeringDBSync(ctx context.Context) {
	syncOnce := func() {
		reqCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()

		req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, peeringDBDumpURL, nil)
		if err != nil {
			log.Printf("peeringdb: request error: %v", err)
			return
		}
		resp, err := peeringHTTPClient.Do(req)
		if err != nil {
			if !errors.Is(err, context.Canceled) {
				log.Printf("peeringdb: download failed: %v", err)
			}
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			log.Printf("peeringdb: unexpected status %s", resp.Status)
			return
		}

		table, err := ParsePeeringDBDump(resp.Body)
		if err != nil {
			log.Printf("peeringdb: parse error: %v", err)
			return
		}
		peeringCache.Store(&table)
		log.Printf("peeringdb: loaded %d ASN connectivity profiles", len(table))
	}

	syncOnce()
	ticker := time.NewTicker(7 * 24 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			syncOnce()
		}
	}
}
