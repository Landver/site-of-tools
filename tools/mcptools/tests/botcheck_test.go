package tests

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"testing"

	"go.mongodb.org/mongo-driver/v2/bson"

	"github.com/Landver/site-of-tools/tools/botcheck"
)

func payload(t *testing.T) map[string]any {
	t.Helper()
	raw, err := os.ReadFile("../../botcheck/tests/testdata/collector_payload.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

var chrome = map[string]string{
	"User-Agent":         "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
	"Accept":             "application/json",
	"Accept-Language":    "en-US,en;q=0.9",
	"Accept-Encoding":    "gzip, deflate, br, zstd",
	"Sec-CH-UA":          `"Chromium";v="125", "Google Chrome";v="125", "Not.A/Brand";v="24"`,
	"Sec-CH-UA-Platform": `"macOS"`,
	"Sec-Fetch-Mode":     "cors",
}

func TestBotcheckScoreSkipsWhatWasNotSupplied(t *testing.T) {
	cs := newStack(t, stackOpts{}).client(t, "/mcp/botcheck", nil)
	got := object(t, call(t, cs, "botcheck_score", map[string]any{
		"http": map[string]any{"user_agent": "curl/8.7.1", "accept": "*/*"}, "detailed": true}))
	checks := map[string]map[string]any{}
	for _, c := range got["checks"].([]any) {
		row := c.(map[string]any)
		checks[row["id"].(string)] = row
	}
	for id, skipped := range map[string]bool{"webdriver": true, "datacenter_ip": true, "fingerprint_reuse": true, "bot_user_agent": false} {
		if checks[id]["skipped"] == true != skipped {
			t.Errorf("%s skipped = %v, want %v", id, checks[id]["skipped"], skipped)
		}
	}
	if checks["bot_user_agent"]["triggered"] != true || got["verdict"] != "bot" || got["attribution"] != nil {
		t.Errorf("curl = %v, bot_user_agent %v; want a bot by its user agent, credited to no one", got["verdict"], checks["bot_user_agent"])
	}
}

func TestBotcheckScoreWritesNoCorpus(t *testing.T) {
	db := liveDB(t, "botcheck_fingerprints")
	count := func() int64 {
		n, err := db.Collection("botcheck_fingerprints").CountDocuments(context.Background(), bson.D{})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	s := newStack(t, stackOpts{corpus: botcheck.NewCorpus(db)})
	fp, _ := json.Marshal(payload(t))
	if rec := s.rest(botHost, "/check", string(fp), nil); rec.Code != http.StatusOK || count() != 1 {
		t.Fatalf("REST POST /check = %d with %d sightings, want 200 and one recorded", rec.Code, count())
	}
	object(t, call(t, s.client(t, "/mcp/botcheck", nil), "botcheck_score", map[string]any{"fingerprint": payload(t), "ip": "203.0.113.50"}))
	if n := count(); n != 1 {
		t.Errorf("after MCP scored the same fingerprint the corpus holds %d sightings, want still 1", n)
	}
}

// corpusSkipped: MCP never echoes the payload, and skips the rules that read the corpus.
func corpusSkipped(body map[string]any) {
	delete(body, "clientPayload")
	cov := body["coverage"].(map[string]any)
	for _, c := range body["checks"].([]any) {
		row := c.(map[string]any)
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

func firedOnly(body map[string]any) {
	fired := []any{}
	for _, c := range body["checks"].([]any) {
		if c.(map[string]any)["triggered"] == true {
			fired = append(fired, c)
		}
	}
	body["checks"] = fired
}
