package tests

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/ciphertools"
)

const signBody = `{"alg":"HS256","key":"0123456789abcdef0123456789abcdef","payload":"{}","now":1700000000}`

// Signing accepts RSA-8192 keys, so it is Heavy, on a budget every app with the same Limits shares.
func TestJWTSignIsHeavy(t *testing.T) {
	if op, _ := ciphertools.Lookup("jwt-sign"); !op.Heavy {
		t.Fatal("jwt-sign is not Heavy")
	}
	lim := ciphertools.NewLimits()
	a, b := engineApp(nil, fstest.MapFS{}, lim), engineApp(nil, fstest.MapFS{}, lim)
	for i := range 5 {
		if rec := do(t, a, http.MethodPost, "/jwt/sign", signBody, "application/json", asAPI); rec.Code != http.StatusOK {
			t.Fatalf("sign %d = %d, want 200 inside the burst of 5: %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := do(t, b, http.MethodPost, "/jwt/sign", signBody, "application/json", asAPI); rec.Code != http.StatusTooManyRequests {
		t.Errorf("sixth sign, on the other app = %d, want 429", rec.Code)
	}
	decode := url.Values{"token": {jwtioToken}}.Encode()
	if rec := do(t, b, http.MethodPost, "/jwt/decode", decode, form, asAPI); rec.Code != http.StatusOK {
		t.Errorf("decode after the heavy budget ran out = %d, want 200: light ops have their own", rec.Code)
	}
}

func post(t *testing.T, e *echo.Echo, path, body, contentType string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- do(t, e, http.MethodPost, path, body, contentType, headers) }()
	select {
	case rec := <-done:
		return rec
	case <-time.After(10 * time.Second):
		t.Fatalf("POST %s waited on the memory budget instead of answering", path)
		return nil
	}
}

// Heavy ops share a memory budget weighed by what they allocate; a light op never asks.
func TestHeavyOpsShareAMemoryBudget(t *testing.T) {
	lim := ciphertools.NewLimits()
	const budget, flat = 256 << 20, 16 << 20
	const otherClient = "198.51.100.250"
	if !lim.HeavyCap.TryAcquire(otherClient, budget-flat) {
		t.Fatal("a fresh budget is under 256 MiB")
	}
	e := engineApp(nil, fstest.MapFS{}, lim)

	argon := `{"password":"pw","algo":"argon2id","argon2_m":65536,"argon2_t":1,"argon2_p":1}`
	rec := post(t, e, "/password/hash", argon, "application/json", asAPI)
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusServiceUnavailable || body["error"] != platform.BusyMessage {
		t.Errorf("64 MiB Argon2 with 16 MiB free = %d %s, want 503 {error: %q}", rec.Code, rec.Body, platform.BusyMessage)
	}
	page := post(t, e, "/password/hash", url.Values{"password": {"pw"}, "algo": {"argon2id"}, "argon2_m": {"65536"}}.Encode(), form, asBrowser)
	if page.Code != http.StatusServiceUnavailable || !strings.Contains(page.Body.String(), platform.BusyMessage) ||
		!strings.Contains(page.Body.String(), `value="65536"`) {
		t.Errorf("no-JS form with the budget spent = %d, want the page saying busy with the form kept", page.Code)
	}
	if rec := post(t, e, "/jwt/sign", signBody, "application/json", asAPI); rec.Code != http.StatusOK {
		t.Errorf("a 16 MiB op in the last 16 MiB = %d %s, want 200", rec.Code, rec.Body)
	}
	hash := url.Values{"text": {"abc"}}.Encode()
	if !lim.HeavyCap.TryAcquire("198.51.100.251", flat) {
		t.Fatal("the signing op did not give its 16 MiB back")
	}
	if rec := post(t, e, "/hash", hash, form, asAPI); rec.Code != http.StatusOK {
		t.Errorf("a light op with the budget spent = %d, want 200", rec.Code)
	}
}

// Limits.Run is the one budget path, REST's and MCP's: a Heavy op past the budget is ErrBusy, a light one runs.
func TestLimitsRunHoldsTheBudget(t *testing.T) {
	lim := ciphertools.NewLimits()
	const budget, client = 256 << 20, "198.51.100.252"
	if !lim.HeavyCap.TryAcquire("198.51.100.253", budget) {
		t.Fatal("a fresh budget is under 256 MiB")
	}
	heavy, _ := ciphertools.Lookup("password-hash")
	bcrypt := ciphertools.Input{Fields: url.Values{"password": {"pw"}, "bcrypt_cost": {"4"}}}
	if _, err := lim.Run(client, heavy, bcrypt); !errors.Is(err, platform.ErrBusy) {
		t.Errorf("heavy op with the budget spent: err = %v, want ErrBusy", err)
	}
	light, _ := ciphertools.Lookup("hash")
	if _, err := lim.Run(client, light, ciphertools.Input{Fields: url.Values{"text": {"abc"}}}); err != nil {
		t.Errorf("light op with the budget spent: %v", err)
	}
	lim.HeavyCap.Release("198.51.100.253", budget)
	if _, err := lim.Run(client, heavy, bcrypt); err != nil {
		t.Errorf("heavy op with the budget free: %v", err)
	}
	if !lim.HeavyCap.TryAcquire(client, budget/4) {
		t.Error("Run kept its share of the budget after returning")
	}
}

func TestHeavyWeightIsBoundedBelow(t *testing.T) {
	tiny := ciphertools.Input{Fields: url.Values{"password": {"pw"}, "algo": {"argon2id"}, "argon2_m": {"8"}, "argon2_p": {"1"}}}
	if got := ciphertools.HeavyWeight("password-hash", tiny); got != 1<<20 {
		t.Errorf("an 8 KiB Argon2 weighs %d, want the 1 MiB floor", got)
	}
	big := ciphertools.Input{Fields: url.Values{"password": {"pw"}, "algo": {"argon2id"}, "argon2_m": {"65536"}}}
	if got, want := ciphertools.HeavyWeight("password-hash", big), ciphertools.MemoryCost("password-hash", big); got != want {
		t.Errorf("a 64 MiB Argon2 weighs %d, want its MemoryCost %d", got, want)
	}
}
