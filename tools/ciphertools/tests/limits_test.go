package tests

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/labstack/echo/v5"

	"github.com/Landver/site-of-tools/platform"
	"github.com/Landver/site-of-tools/tools/ciphertools"
)

const signBody = "key=0123456789abcdef0123456789abcdef"

func TestJWTSignIsHeavy(t *testing.T) {
	lim := ciphertools.NewLimits()
	a, b := cipherApp(nil, nil, lim), cipherApp(nil, nil, lim)
	for i := range 5 {
		if rec := do(t, a, http.MethodPost, "/jwt/sign", signBody, form, asAPI); rec.Code != http.StatusOK {
			t.Fatalf("sign %d = %d, want 200 inside the burst of 5: %s", i+1, rec.Code, rec.Body)
		}
	}
	if rec := do(t, b, http.MethodPost, "/jwt/sign", signBody, form, asAPI); rec.Code != http.StatusTooManyRequests {
		t.Errorf("sixth sign, on the other app = %d, want 429", rec.Code)
	}
	decode := url.Values{"token": {jwtioToken}}.Encode()
	if rec := do(t, b, http.MethodPost, "/jwt/decode", decode, form, asAPI); rec.Code != http.StatusOK {
		t.Errorf("decode after the heavy budget ran out = %d, want 200: light ops have their own", rec.Code)
	}
}

func post(t *testing.T, e *echo.Echo, path, body string, headers map[string]string) *httptest.ResponseRecorder {
	t.Helper()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- do(t, e, http.MethodPost, path, body, form, headers) }()
	select {
	case rec := <-done:
		return rec
	case <-time.After(10 * time.Second):
		t.Fatalf("POST %s waited on the memory budget instead of answering", path)
		return nil
	}
}

func TestHeavyOpsShareAMemoryBudget(t *testing.T) {
	lim := ciphertools.NewLimits()
	const flat = 16 << 20
	if !lim.HeavyCap.TryAcquire("198.51.100.250", 256<<20-flat) {
		t.Fatal("a fresh budget is under 256 MiB")
	}
	e := cipherApp(nil, nil, lim)
	argon := url.Values{"password": {"pw"}, "algo": {"argon2id"}, "argon2_m": {"65536"}}.Encode()
	for _, h := range []map[string]string{asAPI, asBrowser} {
		if rec := post(t, e, "/password/hash", argon, h); rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), platform.BusyMessage) {
			t.Errorf("64 MiB Argon2 with 16 MiB free, Accept %s = %d, want 503 saying busy", h["Accept"], rec.Code)
		}
	}
	if rec := post(t, e, "/jwt/sign", signBody, asAPI); rec.Code != http.StatusOK {
		t.Errorf("a 16 MiB op in the last 16 MiB = %d %s, want 200", rec.Code, rec.Body)
	}
	if !lim.HeavyCap.TryAcquire("198.51.100.251", flat) {
		t.Fatal("the signing op did not give its 16 MiB back")
	}
	if rec := post(t, e, "/hash", "text=abc", asAPI); rec.Code != http.StatusOK {
		t.Errorf("a light op with the budget spent = %d, want 200", rec.Code)
	}
}

func TestHeavyWeight(t *testing.T) {
	const flat = 16 << 20
	salt, sum := base64.RawStdEncoding.EncodeToString([]byte("sixteen byte salt")), base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	argon2 := func(m int) string { return fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=4$%s$%s", m, salt, sum) }
	scrypt := fmt.Sprintf("$scrypt$ln=15,r=8,p=3$%s$%s", salt, sum)
	cases := []struct {
		name, op string
		fields   url.Values
		want     int64
	}{
		{"bcrypt", "password-hash", url.Values{"bcrypt_cost": {"14"}}, flat},
		{"argon2id below the floor", "password-hash", url.Values{"algo": {"argon2id"}, "argon2_m": {"8"}}, 1 << 20},
		{"argon2id at the cap", "password-hash", url.Values{"algo": {"Argon2id"}, "argon2_m": {"65536"}, "argon2_p": {"4"}}, 64 << 20},
		{"argon2id refused", "password-hash", url.Values{"algo": {"argon2id"}, "argon2_m": {"65537"}}, flat},
		{"scrypt at the cap", "password-hash", url.Values{"algo": {"scrypt"}, "scrypt_n": {"131072"}, "scrypt_p": {"4"}}, 128 * 8 * (1<<17 + 4 + 2)},
		{"verify argon2id", "password-verify", url.Values{"hash": {argon2(65536)}, "password": {"pw"}}, 64 << 20},
		{"verify scrypt", "password-verify", url.Values{"hash": {scrypt}, "password": {"pw"}}, 128 * 8 * (1<<15 + 3 + 2)},
		{"verify reads only", "password-verify", url.Values{"hash": {argon2(65536)}}, flat},
		{"verify refused", "password-verify", url.Values{"hash": {argon2(1 << 20)}, "password": {"pw"}}, flat},
		{"verify garbage", "password-verify", url.Values{"hash": {"$2b$nope"}, "password": {"pw"}}, flat},
		{"keys-generate", "keys-generate", url.Values{"type": {"rsa-4096"}}, flat},
	}
	for _, c := range cases {
		if got := ciphertools.HeavyWeight(c.op, ciphertools.Input{Fields: c.fields}); got != c.want {
			t.Errorf("%s: HeavyWeight = %d, want %d", c.name, got, c.want)
		}
	}
}

func TestMemoryCostMatchesAllocation(t *testing.T) {
	for _, fields := range []url.Values{
		{"algo": {"argon2id"}, "argon2_m": {"8192"}, "argon2_t": {"1"}, "argon2_p": {"2"}},
		{"algo": {"scrypt"}, "scrypt_n": {"8192"}, "scrypt_r": {"8"}, "scrypt_p": {"2"}},
	} {
		cost := ciphertools.MemoryCost("password-hash", ciphertools.Input{Fields: fields})
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		if _, err := runOp(t, "password-hash", fields, nil); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		if got := int64(after.TotalAlloc - before.TotalAlloc); got < cost-64<<10 || got > cost+1<<20 {
			t.Errorf("%s: charged %d bytes, allocated %d", fields.Get("algo"), cost, got)
		}
	}
}
