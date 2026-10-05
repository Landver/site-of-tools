package tests

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"runtime"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

func TestMemoryCost(t *testing.T) {
	const flat = 16 << 20
	salt, sum := base64.RawStdEncoding.EncodeToString([]byte("sixteen byte salt")), base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	argon2 := func(m int) string { return fmt.Sprintf("$argon2id$v=19$m=%d,t=1,p=4$%s$%s", m, salt, sum) }
	scrypt := func(ln, r, p int) string { return fmt.Sprintf("$scrypt$ln=%d,r=%d,p=%d$%s$%s", ln, r, p, salt, sum) }
	cases := []struct {
		name, op string
		fields   url.Values
		want     int64
	}{
		{"bcrypt", "password-hash", url.Values{"bcrypt_cost": {"14"}}, flat},
		{"argon2id default", "password-hash", url.Values{"algo": {"argon2id"}}, 19456 << 10},
		{"argon2id at the cap", "password-hash", url.Values{"algo": {"Argon2id"}, "argon2_m": {"65536"}, "argon2_p": {"4"}}, 64 << 20},
		{"argon2id refused", "password-hash", url.Values{"algo": {"argon2id"}, "argon2_m": {"65537"}}, flat},
		{"scrypt default", "password-hash", url.Values{"algo": {"scrypt"}}, 128 * 8 * (1<<15 + 3 + 2)},
		{"scrypt at the cap", "password-hash", url.Values{"algo": {"scrypt"}, "scrypt_n": {"131072"}, "scrypt_p": {"4"}}, 128 * 8 * (1<<17 + 4 + 2)},
		{"scrypt refused", "password-hash", url.Values{"algo": {"scrypt"}, "scrypt_n": {"131072"}, "scrypt_r": {"16"}}, flat},
		{"pbkdf2", "password-hash", url.Values{"algo": {"pbkdf2-sha512"}}, flat},
		{"verify argon2id", "password-verify", url.Values{"hash": {argon2(65536)}, "password": {"pw"}}, 64 << 20},
		{"verify scrypt", "password-verify", url.Values{"hash": {scrypt(15, 8, 3)}, "password": {"pw"}}, 128 * 8 * (1<<15 + 3 + 2)},
		{"verify reads only", "password-verify", url.Values{"hash": {argon2(65536)}}, flat},
		{"verify refused", "password-verify", url.Values{"hash": {argon2(1 << 20)}, "password": {"pw"}}, flat},
		{"verify refused scrypt", "password-verify", url.Values{"hash": {scrypt(40, 8, 1)}, "password": {"pw"}}, flat},
		{"verify garbage", "password-verify", url.Values{"hash": {"$2b$nope"}, "password": {"pw"}}, flat},
		{"keys-generate", "keys-generate", url.Values{"type": {"rsa-4096"}}, flat},
		{"hash", "hash", url.Values{"text": {strings.Repeat("x", 1<<20)}}, flat},
		{"unknown op", "nope", url.Values{}, flat},
	}
	for _, c := range cases {
		if got := ciphertools.MemoryCost(c.op, ciphertools.Input{Fields: c.fields}); got != c.want {
			t.Errorf("%s: MemoryCost = %d, want %d", c.name, got, c.want)
		}
	}
}

// The charge is what hashing really allocates: Argon2's m KiB and scrypt's
// 128·N·r whatever p is, since neither allocates per lane.
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
