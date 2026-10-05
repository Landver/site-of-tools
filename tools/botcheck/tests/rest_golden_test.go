package tests

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

const (
	applebotUA  = "Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)"
	electronUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Electron/31.2.0 Safari/537.36"
	winChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

// browserHeaders is what desktop Chrome sends alongside the collector's JSON
// POST, Accept aside.
func browserHeaders() map[string]string {
	return map[string]string{
		"Accept":                    "application/json",
		"User-Agent":                chromeMacUA,
		"Accept-Encoding":           "gzip, deflate, br, zstd",
		"Accept-Language":           "en-US,en;q=0.9",
		"Sec-CH-UA":                 `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"`,
		"Sec-CH-UA-Platform":        `"macOS"`,
		"Sec-Fetch-Mode":            "cors",
		"Upgrade-Insecure-Requests": "1",
	}
}

func with(h map[string]string, kv ...string) map[string]string {
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] == "" {
			delete(h, kv[i])
		} else {
			h[kv[i]] = kv[i+1]
		}
	}
	return h
}

// collectorPayload is testdata/collector_payload.json (a real v4 collector
// shape, clean desktop Chrome) with the given top-level keys overridden.
func collectorPayload(t *testing.T, overrides map[string]any) string {
	t.Helper()
	raw, err := os.ReadFile("testdata/collector_payload.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range overrides {
		m[k] = v
	}
	out, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

type fakeChecker struct {
	lk  iptools.BlockLookup
	err error
}

func (f fakeChecker) Check(context.Context, string) (iptools.BlockLookup, error) { return f.lk, f.err }

func listedBy(count int, sources ...string) fakeChecker {
	return fakeChecker{lk: iptools.BlockLookup{Sources: sources, MaxCount: count}}
}

type restCase struct {
	name    string
	svc     botcheck.Looker
	chk     iptools.Checker
	hdr     map[string]string
	payload string // POST /check only
}

func serveBotcheck(c restCase, method, target string) *httptest.ResponseRecorder {
	e := echo.New()
	botcheck.Register(e, c.svc, nil, c.chk, nil)
	req := httptest.NewRequest(method, target, strings.NewReader(c.payload))
	if method == http.MethodPost {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.hdr {
		req.Header.Set(k, v)
	}
	req.RemoteAddr = "203.0.113.50:4321"
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	return rec
}

var (
	kddi       = &iptools.Result{Timezone: "+09:00", ASN: "2516", ASName: "KDDI CORPORATION"}
	awsDC      = &iptools.Result{Timezone: "+09:00", ASN: "16509", ASName: "Amazon.com, Inc.", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "DCH", Provider: "Amazon"}}
	moscowVPN  = &iptools.Result{Timezone: "+03:00", ASN: "9009", ASName: "M247 Europe SRL", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "VPN", Provider: "NordVPN"}}
	placeholds = &iptools.Result{Timezone: "-", ASN: "-", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "PUB"}}
	torExit    = &iptools.Result{Timezone: "+01:00", ASN: "60729", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "TOR"}}
	appleNet   = &iptools.Result{Timezone: "-07:00", ASN: "714", ASName: "Apple Inc."}
)

func serverOnlyCases() []restCase {
	return []restCase{
		{name: "browser_datacenter", svc: fakeLooker{res: awsDC}, hdr: browserHeaders()},
		{name: "curl_no_geo", svc: fakeLooker{err: iptools.ErrUnavailable}, hdr: map[string]string{"Accept": "*/*", "User-Agent": "curl/8.7.1"}},
		{name: "applebot_verified", svc: fakeLooker{res: appleNet}, hdr: map[string]string{"Accept": "application/json", "User-Agent": applebotUA}},
		{name: "bare_browser_ua_placeholders", svc: fakeLooker{res: placeholds}, hdr: map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA}},
		{name: "electron_tor", svc: fakeLooker{res: torExit}, hdr: with(browserHeaders(), "User-Agent", electronUA)},
		{name: "ipsum_at_floor", svc: fakeLooker{res: kddi}, chk: listedBy(3, "ipsum"), hdr: browserHeaders()},
		{name: "ipsum_below_floor", svc: fakeLooker{res: kddi}, chk: listedBy(2, "ipsum"), hdr: browserHeaders()},
		{name: "applebot_blocklisted", svc: fakeLooker{res: appleNet}, chk: listedBy(8, "ipsum"), hdr: map[string]string{"Accept": "application/json", "User-Agent": applebotUA}},
		{name: "blocklist_read_failed_no_geo", svc: fakeLooker{err: iptools.ErrUnavailable}, chk: fakeChecker{err: errors.New("mongo down")}, hdr: browserHeaders()},
	}
}

func fingerprintCases(t *testing.T) []restCase {
	clean := collectorPayload(t, nil)
	stealth := collectorPayload(t, map[string]any{
		"cdpMainThread":          true,
		"swPlatform":             "Linux",
		"webrtcIPs":              []string{"192.168.1.23", "198.51.100.77"},
		"notificationPermission": "denied",
		"plugins":                0,
		"fontCount":              0,
	})
	return []restCase{
		{name: "clean_full_headers", svc: fakeLooker{res: kddi}, hdr: browserHeaders(), payload: clean},
		{name: "clean_sparse_headers_no_geo", svc: fakeLooker{err: iptools.ErrUnavailable}, hdr: map[string]string{"Accept": "*/*", "User-Agent": chromeMacUA}, payload: clean},
		{name: "ua_header_rewritten", svc: fakeLooker{res: kddi}, hdr: with(browserHeaders(), "User-Agent", winChromeUA, "Sec-CH-UA-Platform", `"Windows"`), payload: clean},
		{name: "stealth_vpn", svc: fakeLooker{res: moscowVPN}, hdr: with(browserHeaders(), "Accept-Language", "fr-FR,fr;q=0.9", "Accept-Encoding", ""), payload: stealth},
		{name: "deliberate_ban_no_geo", svc: fakeLooker{err: iptools.ErrUnavailable}, chk: listedBy(0, "rate-limiter"), hdr: browserHeaders(), payload: clean},
		{name: "spamhaus_counts_as_deliberate", svc: fakeLooker{res: kddi}, chk: listedBy(1, "ipsum", "spamhaus-drop"), hdr: browserHeaders(), payload: clean},
	}
}

func TestServerSignalsJSONGolden(t *testing.T) {
	got := map[string]*httptest.ResponseRecorder{}
	for _, c := range serverOnlyCases() {
		got[c.name] = serveBotcheck(c, http.MethodGet, "/")
	}
	checkGolden(t, "server_signals", got)
}

func TestCheckJSONGolden(t *testing.T) {
	got := map[string]*httptest.ResponseRecorder{}
	for _, c := range fingerprintCases(t) {
		got[c.name] = serveBotcheck(c, http.MethodPost, "/check")
	}
	checkGolden(t, "check", got)
}
