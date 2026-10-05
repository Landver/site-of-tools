package tests

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/labstack/echo/v5"
	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/botcheck"
	"github.com/Landver/site-of-tools/tools/iptools"
)

const chromeMacUA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"

// payload is botcheck's own collector fixture, a real v4 payload from clean
// desktop Chrome, with keys set or (nil) removed.
func payload(t *testing.T, change map[string]any) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../botcheck/tests/testdata/collector_payload.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	for k, v := range change {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	return m
}

// chromeHTTP is what that browser sends with the collector's POST, as the
// http argument and as REST request headers.
var chromeHTTP = map[string]string{
	"user_agent":         chromeMacUA,
	"accept":             "application/json",
	"accept_language":    "en-US,en;q=0.9",
	"accept_encoding":    "gzip, deflate, br, zstd",
	"sec_ch_ua":          `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"`,
	"sec_ch_ua_platform": `"macOS"`,
	"sec_fetch_mode":     "cors",
}

func httpArg(h map[string]string) map[string]any {
	out := map[string]any{}
	for k, v := range h {
		out[k] = v
	}
	return out
}

// headerOf is the request header each http argument stands for.
var headerOf = map[string]string{
	"user_agent": "User-Agent", "accept": "Accept", "accept_language": "Accept-Language",
	"accept_encoding": "Accept-Encoding", "sec_ch_ua": "Sec-CH-UA",
	"sec_ch_ua_platform": "Sec-CH-UA-Platform", "sec_fetch_mode": "Sec-Fetch-Mode",
}

func restHeaders(h map[string]string, ip string) map[string]string {
	out := map[string]string{"Host": botHost, "CF-Connecting-IP": ip}
	for k, v := range h {
		out[headerOf[k]] = v
	}
	return out
}

// checkRows are a report's checks by id.
func checkRows(t *testing.T, got map[string]any) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, row := range rows(t, got, "checks") {
		out[row["id"].(string)] = row
	}
	return out
}

func TestBotcheckScoreNeedsSomethingToScore(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/botcheck", nil, nil)
	for _, args := range []map[string]any{{}, {"detailed": true}, {"ip": "  "}} {
		failsWith(t, call(t, cs, "botcheck_score", args), "Nothing to score: pass fingerprint")
	}
}

func TestBotcheckScoreFingerprintIsACollectorPayload(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/botcheck", nil, nil)
	for _, tc := range []struct {
		fp   any
		want string
	}{
		{payload(t, map[string]any{"v": nil}), "no v version stamp"},
		{payload(t, map[string]any{"v": 0}), "no v version stamp"},
		{map[string]any{"webdriver": true}, "no v version stamp"},
		{payload(t, map[string]any{"injected": "x"}), `unknown field "injected"`},
		{payload(t, map[string]any{"plugins": "five"}), "plugins"},
		{"v=4", "fingerprint"},
	} {
		failsWith(t, call(t, cs, "botcheck_score", map[string]any{"fingerprint": tc.fp}), tc.want)
	}
	failsWith(t, call(t, cs, "botcheck_score", map[string]any{"ip": "not-an-ip"}), `"not-an-ip" is not an IP address`)
}

// TestBotcheckScoreSkipsWhatWasNotSupplied: headers alone evaluate the header
// rules and skip the client and IP ones, and the coverage counts say so.
func TestBotcheckScoreSkipsWhatWasNotSupplied(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/botcheck", nil, nil)
	curl := map[string]any{"http": map[string]any{"user_agent": "curl/8.7.1", "accept": "*/*"}}
	got := object(t, call(t, cs, "botcheck_score", map[string]any{"http": curl["http"], "detailed": true}))
	checks := checkRows(t, got)
	for id, skipped := range map[string]bool{"webdriver": true, "software_renderer": true, "datacenter_ip": true,
		"ip_blocklisted": true, "fingerprint_reuse": true, "bot_user_agent": false} {
		if checks[id]["skipped"] == true != skipped {
			t.Errorf("%s skipped = %v, want %v", id, checks[id]["skipped"], skipped)
		}
	}
	if checks["bot_user_agent"]["triggered"] != true || got["verdict"] != "bot" {
		t.Errorf("curl = %v, bot_user_agent %v; want a bot by its user agent", got["verdict"], checks["bot_user_agent"])
	}
	cov := got["coverage"].(map[string]any)
	total := 0
	for _, tier := range []string{"hard", "consistency", "soft"} {
		c := cov[tier].(map[string]any)
		ev, _ := c["evaluated"].(json.Number).Int64()
		sk, _ := c["skipped"].(json.Number).Int64()
		total += int(ev + sk)
		if sk == 0 {
			t.Errorf("%s tier skipped nothing without a fingerprint or an IP: %v", tier, c)
		}
	}
	if total != len(checks) {
		t.Errorf("coverage counts %d checks of %d", total, len(checks))
	}

	concise := object(t, call(t, cs, "botcheck_score", curl))
	for _, row := range rows(t, concise, "checks") {
		if row["triggered"] != true {
			t.Errorf("concise lists %s, which didn't fire", row["id"])
		}
	}
	if len(rows(t, concise, "checks")) == 0 || concise["attribution"] != nil {
		t.Errorf("concise = %v, want the fired checks and no attribution without an ip", concise)
	}
}

// TestBotcheckScoreCorpusRulesAreNotEvaluated: a synthetic payload must not
// train the corpus, so the two rules reading it skip, where REST evaluates.
func TestBotcheckScoreCorpusRulesAreNotEvaluated(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/botcheck", nil, nil)
	got := object(t, call(t, cs, "botcheck_score", map[string]any{"fingerprint": payload(t, nil),
		"http": httpArg(chromeHTTP), "ip": "203.0.113.50", "detailed": true}))
	checks := checkRows(t, got)
	for _, id := range []string{"fingerprint_reuse", "ip_fingerprint_churn"} {
		if checks[id]["skipped"] != true {
			t.Errorf("%s = %v, want skipped", id, checks[id])
		}
	}
	if checks["webdriver"]["skipped"] == true || checks["ua_header_mismatch"]["skipped"] == true {
		t.Errorf("client rules skipped with a fingerprint given: %v %v", checks["webdriver"], checks["ua_header_mismatch"])
	}
	if _, ok := got["clientPayload"]; ok {
		t.Error("the fingerprint is echoed back")
	}
}

// TestBotcheckScoreWritesNoCorpus: REST's POST /check records the fingerprint
// it scores; MCP, scoring the same one, records nothing. Needs MONGODB_TEST_URI.
func TestBotcheckScoreWritesNoCorpus(t *testing.T) {
	if os.Getenv("MONGODB_TEST_URI") == "" {
		t.Skip("MONGODB_TEST_URI not set; skipping the corpus write check")
	}
	m, err := liveMongo()
	if err != nil {
		t.Fatalf("open mongo: %v", err)
	}
	ctx := context.Background()
	coll := m.DB().Collection("botcheck_fingerprints")
	if err := coll.Drop(ctx); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = coll.Drop(ctx) })
	count := func() int64 {
		n, err := coll.CountDocuments(ctx, bson.D{})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}

	fp, _ := json.Marshal(payload(t, nil))
	e := echo.New()
	botcheck.Register(e, nil, botcheck.NewCorpus(m.DB()), nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/check", strings.NewReader(string(fp)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || count() != 1 {
		t.Fatalf("REST POST /check = %d with %d sightings, want 200 and one recorded", rec.Code, count())
	}
	cs := newStack(t, stackOpts{}).client(t, "/mcp/botcheck", nil, nil)
	object(t, call(t, cs, "botcheck_score", map[string]any{"fingerprint": payload(t, nil), "ip": "203.0.113.50"}))
	if n := count(); n != 1 {
		t.Errorf("after MCP scored the same fingerprint the corpus holds %d sightings, want still 1", n)
	}
}

func TestBotcheckScoreAttribution(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/botcheck", nil, nil)
	got := object(t, call(t, cs, "botcheck_score", map[string]any{"ip": " 8.8.8.8 "}))
	if diff := cmp.Diff([]string{"IP2Location LITE", "The Spamhaus Project", "Shodan InternetDB"}, sources(t, got)); diff != "" {
		t.Errorf("attribution with an ip (-want +got):\n%s", diff)
	}

	r := richResult
	r.Shodan = &iptools.ShodanInfo{Skipped: true}
	skipped := newStack(t, stackOpts{geo: &fakeGeo{res: r}}).client(t, "/mcp/botcheck", nil, nil)
	got = object(t, call(t, skipped, "botcheck_score", map[string]any{"ip": "8.8.8.8"}))
	if diff := cmp.Diff([]string{"IP2Location LITE", "The Spamhaus Project"}, sources(t, got)); diff != "" {
		t.Errorf("attribution when Shodan was skipped (-want +got):\n%s", diff)
	}
}

// corpusProjection is what MCP declares against POST /check: no echo of the
// payload, and the corpus rules skipped instead of evaluated.
func corpusProjection(t *testing.T, body map[string]any) {
	t.Helper()
	delete(body, "clientPayload")
	cov := body["coverage"].(map[string]any)
	for _, row := range rows(t, body, "checks") {
		if id := row["id"]; id != "fingerprint_reuse" && id != "ip_fingerprint_churn" {
			continue
		}
		row["skipped"] = true
		tier := cov[row["tier"].(string)].(map[string]any)
		ev, _ := tier["evaluated"].(json.Number).Int64()
		sk, _ := tier["skipped"].(json.Number).Int64()
		tier["evaluated"], tier["skipped"] = num(int(ev-1)), num(int(sk+1))
	}
}

// TestBotcheckParity: detailed is the REST report for the same headers, IP
// and fingerprint, through the declared projections; concise is detailed
// with only the fired checks.
func TestBotcheckParity(t *testing.T) {
	s := newStack(t, stackOpts{})
	cs := s.client(t, "/mcp", nil, nil)
	const ip = "203.0.113.50"
	fp := payload(t, nil)
	body, _ := json.Marshal(fp)
	for _, tc := range []struct {
		name    string
		args    map[string]any
		method  string
		target  string
		body    string
		project func(*testing.T, map[string]any)
	}{
		{"server signals", map[string]any{"http": httpArg(chromeHTTP), "ip": ip}, http.MethodGet, "/", "", nil},
		{"fingerprint", map[string]any{"fingerprint": fp, "http": httpArg(chromeHTTP), "ip": ip}, http.MethodPost, "/check", string(body), corpusProjection},
	} {
		hdr := restHeaders(chromeHTTP, ip)
		if tc.body != "" {
			hdr["Content-Type"] = "application/json"
		}
		rec := s.do(tc.method, tc.target, tc.body, hdr)
		if rec.Code != http.StatusOK {
			t.Fatalf("REST %s %s = %d %s", tc.method, tc.target, rec.Code, rec.Body)
		}
		// The browser's Accept-Encoding is a scored header, so the reply is gzipped.
		zr, err := gzip.NewReader(rec.Body)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := io.ReadAll(zr)
		if err != nil {
			t.Fatal(err)
		}
		want := decode(t, raw)
		if tc.project != nil {
			tc.project(t, want)
		}
		args := map[string]any{"detailed": true}
		for k, v := range tc.args {
			args[k] = v
		}
		detailed := object(t, call(t, cs, "botcheck_score", args))
		delete(detailed, "attribution")
		if diff := cmp.Diff(want, detailed); diff != "" {
			t.Errorf("%s: detailed vs REST %s %s (-rest +mcp):\n%s", tc.name, tc.method, tc.target, diff)
		}

		concise := object(t, call(t, cs, "botcheck_score", tc.args))
		delete(concise, "attribution")
		fired := []any{}
		for _, row := range want["checks"].([]any) {
			if row.(map[string]any)["triggered"] == true {
				fired = append(fired, row)
			}
		}
		want["checks"] = fired
		if diff := cmp.Diff(want, concise); diff != "" {
			t.Errorf("%s: concise vs REST with the fired checks only (-rest +mcp):\n%s", tc.name, diff)
		}
	}
}

// TestBotcheckBudgetWhicheverDoor: scores spent over REST are spent over MCP,
// and a full concurrency cap answers busy.
func TestBotcheckBudgetWhicheverDoor(t *testing.T) {
	const client = "198.51.100.80"
	lim := botcheck.NewLimits()
	s := newStack(t, stackOpts{botLim: lim})
	cs := s.client(t, "/mcp/botcheck", map[string]string{"CF-Connecting-IP": client}, nil)
	args := map[string]any{"http": map[string]any{"user_agent": "curl/8.7.1"}}
	for i := 0; s.do(http.MethodGet, "/", "", map[string]string{"Host": botHost, "Accept": "application/json", "CF-Connecting-IP": client}).Code != http.StatusTooManyRequests; i++ {
		if i == 30 {
			t.Fatal("the REST score budget never ran out")
		}
	}
	if res := call(t, cs, "botcheck_score", args); !res.IsError || text(t, res) != limitedText {
		t.Errorf("MCP after REST spent the budget = %q, want limited", text(t, res))
	}

	lim = roomyBot()
	cs = newStack(t, stackOpts{botLim: lim}).client(t, "/mcp/botcheck", nil, nil)
	lim.CheckCap.TryAcquire(otherClient, 8)
	if res := call(t, cs, "botcheck_score", args); !res.IsError || text(t, res) != platform.BusyMessage {
		t.Errorf("full cap = %q, want busy", text(t, res))
	}
	lim.CheckCap.Release(otherClient, 8)
	object(t, call(t, cs, "botcheck_score", args))
}
