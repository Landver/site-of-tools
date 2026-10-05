package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/Landver/site-of-tools/platform/goldentest"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

const (
	applebotUA  = "Mozilla/5.0 (Applebot/0.1; +http://www.apple.com/go/applebot)"
	electronUA  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Electron/31.2.0 Safari/537.36"
	winChromeUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
)

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
	payload string // POST /check when set, else GET /
}

var (
	kddi       = &iptools.Result{Timezone: "+09:00", ASN: "2516", ASName: "KDDI CORPORATION"}
	awsDC      = &iptools.Result{Timezone: "+09:00", ASN: "16509", ASName: "Amazon.com, Inc.", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "DCH", Provider: "Amazon"}}
	moscowVPN  = &iptools.Result{Timezone: "+03:00", ASN: "9009", ASName: "M247 Europe SRL", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "VPN", Provider: "NordVPN"}}
	placeholds = &iptools.Result{Timezone: "-", ASN: "-", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "PUB"}}
	torExit    = &iptools.Result{Timezone: "+01:00", ASN: "60729", Proxy: &iptools.Proxy{IsProxy: true, ProxyType: "TOR"}}
	appleNet   = &iptools.Result{Timezone: "-07:00", ASN: "714", ASName: "Apple Inc."}
)

// golden pins case full's whole report, and of the rest what the verdict rests on.
func golden(t *testing.T, name, full string, cases []restCase) {
	t.Helper()
	pinned := map[string]any{}
	for _, c := range cases {
		app := newAppWith(c.svc, c.chk, nil)
		app.IPExtractor = func(*http.Request) string { return "203.0.113.50" }
		var rec *httptest.ResponseRecorder
		if c.payload == "" {
			rec = get(app, "/", c.hdr)
		} else {
			rec = post(app, "/check", c.payload, c.hdr)
		}
		if c.name == full {
			pinned[c.name] = goldentest.Response{Status: rec.Code, Body: rec.Body.Bytes()}
			continue
		}
		var r botcheck.Report
		if err := json.Unmarshal(rec.Body.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		fired := []string{}
		for _, ch := range r.Checks {
			if ch.Triggered {
				fired = append(fired, ch.ID)
			}
		}
		pinned[c.name] = map[string]any{"status": rec.Code, "score": r.Score, "verdict": r.Verdict, "bot": r.Bot,
			"coverage": r.Coverage, "fired": fired}
	}
	goldentest.JSON(t, name, pinned)
}

func TestServerSignalsJSONGolden(t *testing.T) {
	golden(t, "server_signals", "", []restCase{
		{name: "browser_datacenter", svc: fakeLooker{res: awsDC}, hdr: browserHeaders()},
		{name: "curl_no_geo", svc: fakeLooker{err: iptools.ErrUnavailable}, hdr: map[string]string{"Accept": "*/*", "User-Agent": "curl/8.7.1"}},
		{name: "applebot_verified", svc: fakeLooker{res: appleNet}, hdr: map[string]string{"Accept": "application/json", "User-Agent": applebotUA}},
		{name: "bare_browser_ua_placeholders", svc: fakeLooker{res: placeholds}, hdr: map[string]string{"Accept": "application/json", "User-Agent": chromeMacUA}},
		{name: "electron_tor", svc: fakeLooker{res: torExit}, hdr: with(browserHeaders(), "User-Agent", electronUA)},
		{name: "ipsum_at_floor", svc: fakeLooker{res: kddi}, chk: listedBy(3, "ipsum"), hdr: browserHeaders()},
		{name: "ipsum_below_floor", svc: fakeLooker{res: kddi}, chk: listedBy(2, "ipsum"), hdr: browserHeaders()},
	})
}

func TestCheckJSONGolden(t *testing.T) {
	clean := collectorPayload(t, nil)
	stealth := collectorPayload(t, map[string]any{
		"cdpMainThread":          true,
		"swPlatform":             "Linux",
		"webrtcIPs":              []string{"192.168.1.23", "198.51.100.77"},
		"notificationPermission": "denied",
		"plugins":                0,
		"fontCount":              0,
	})
	golden(t, "check", "stealth_vpn", []restCase{
		{name: "clean_full_headers", svc: fakeLooker{res: kddi}, hdr: browserHeaders(), payload: clean},
		{name: "clean_sparse_headers_no_geo", svc: fakeLooker{err: iptools.ErrUnavailable}, hdr: map[string]string{"Accept": "*/*", "User-Agent": chromeMacUA}, payload: clean},
		{name: "ua_header_rewritten", svc: fakeLooker{res: kddi}, hdr: with(browserHeaders(), "User-Agent", winChromeUA, "Sec-CH-UA-Platform", `"Windows"`), payload: clean},
		{name: "stealth_vpn", svc: fakeLooker{res: moscowVPN}, hdr: with(browserHeaders(), "Accept-Language", "fr-FR,fr;q=0.9", "Accept-Encoding", ""), payload: stealth},
		{name: "deliberate_ban_no_geo", svc: fakeLooker{err: iptools.ErrUnavailable}, chk: listedBy(0, "rate-limiter"), hdr: browserHeaders(), payload: clean},
	})
}
