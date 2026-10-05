package tests

import (
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// fieldInputs gives an accepted input whose code path reads the field (kind=uuid for version).
func fieldInputs(t *testing.T) func(op, field string) url.Values {
	t.Helper()
	key := strings.Repeat("ab", 32)
	decrypt := url.Values{"mode": {"decrypt"}, "key": {key},
		"data": {encryptOf(t, url.Values{"key": {key}, "text": {"hi"}}).Combined.Base64}}
	argon2, scrypt := pwFields("argon2id", "pw"), pwFields("scrypt", "pw")
	password, uuid := url.Values{"kind": {"password"}}, url.Values{"kind": {"uuid"}}
	base := map[string]url.Values{
		"jwt-decode":      {"token": {jwtioToken}, "key": {"your-256-bit-secret"}},
		"jwt-sign":        {"key": {"0123456789abcdef0123456789abcdef"}},
		"hash":            {"text": {"abc"}},
		"hmac":            {"text": {"abc"}, "key": {"abc"}},
		"password-hash":   {"password": {"pw"}, "bcrypt_cost": {"4"}},
		"password-verify": {"hash": {pwHash(t, url.Values{"password": {"pw"}, "bcrypt_cost": {"4"}}).Encoded}, "password": {"pw"}},
		"encrypt":         {"text": {"hi"}},
		"keys-generate":   {},
		"keys-inspect":    {"key": {rfcEdKey}},
		"cert":            {"cert": {pemOf(newPKI(t).leaf)}},
		"totp":            {"secret": {"JBSWY3DPEHPK3PXP"}},
		"random":          {},
		"encode":          {"text": {"abc"}},
		"basic":           {"user": {"u"}, "password": {"p"}},
		"identify":        {"text": {"abc"}},
	}
	branch := map[string]url.Values{
		"password-hash algo": {"argon2_m": {"8"}, "argon2_t": {"1"}, "argon2_p": {"1"},
			"scrypt_n": {"1024"}, "scrypt_r": {"1"}, "scrypt_p": {"1"}, "pbkdf2_iterations": {"1000"}},
		"password-hash argon2_m": argon2, "password-hash argon2_t": argon2, "password-hash argon2_p": argon2,
		"password-hash scrypt_n": scrypt, "password-hash scrypt_r": scrypt, "password-hash scrypt_p": scrypt,
		"password-hash pbkdf2_iterations": {"algo": {"pbkdf2-sha256"}},
		"encrypt key_enc":                 {"key": {key}},
		"encrypt aad_enc":                 {"aad": {"abc"}},
		"encrypt data":                    decrypt,
		"encrypt data_enc":                decrypt,
		"random length":                   password,
		"random sets":                     password,
		"random exclude_ambiguous":        password,
		"random version":                  uuid,
		"random count":                    uuid, // the widest bound
		"totp counter":                    {"mode": {"hotp"}},
	}
	for _, op := range ciphertools.Ops() {
		if _, ok := base[op.Name]; !ok {
			t.Fatalf("fieldInputs has no input for %s", op.Name)
		}
	}
	return func(op, field string) url.Values {
		in := url.Values{}
		for _, src := range []url.Values{base[op], branch[op+" "+field]} {
			for k, v := range src {
				in[k] = slices.Clone(v)
			}
		}
		return in
	}
}

// refusal is the op's error, or the key error jwt-decode reports in its result.
func refusal(res any, err error) string {
	if err != nil {
		return err.Error()
	}
	if j, ok := res.(*ciphertools.JWT); ok && j.Verification.State == ciphertools.VerifyError {
		return j.Verification.Detail
	}
	return ""
}

func TestIntFieldBounds(t *testing.T) {
	input := fieldInputs(t)
	for _, op := range ciphertools.Ops() {
		for _, f := range op.Fields {
			if f.Kind != ciphertools.KindInt {
				continue
			}
			type try struct {
				v  string
				ok bool
			}
			var tries []try
			if f.Min != nil {
				tries = append(tries, try{strconv.Itoa(*f.Min - 1), false}, try{strconv.Itoa(*f.Min), true})
			}
			if f.Max != nil {
				tries = append(tries, try{strconv.FormatUint(uint64(*f.Max)+1, 10), false}, try{strconv.Itoa(*f.Max), true})
			}
			for _, tr := range tries {
				// At the caps Heavy ops take seconds, and intField reads their bounds from the spec.
				if tr.ok && op.Heavy {
					continue
				}
				in := input(op.Name, f.Name)
				in.Set(f.Name, tr.v)
				_, err := runOp(t, op.Name, in, nil)
				switch {
				case tr.ok && err != nil:
					t.Errorf("%s %s=%s is within the spec's bounds but fails: %v", op.Name, f.Name, tr.v, err)
				case !tr.ok && (err == nil || !strings.Contains(err.Error(), f.Name)):
					t.Errorf("%s %s=%s is outside the spec's bounds: got error %v, want one naming %s", op.Name, f.Name, tr.v, err, f.Name)
				}
			}
		}
	}
}

func TestEnumFieldsRefuseOtherValues(t *testing.T) {
	input := fieldInputs(t)
	for _, op := range ciphertools.Ops() {
		for _, f := range op.Fields {
			if len(f.Enum) == 0 {
				continue
			}
			bad := "bogus-value"
			if f.Kind == ciphertools.KindInt {
				for n := *f.Min; n <= *f.Max; n++ {
					if !slices.Contains(f.Enum, strconv.Itoa(n)) {
						bad = strconv.Itoa(n)
						break
					}
				}
			}
			in := input(op.Name, f.Name)
			in.Set(f.Name, bad)
			if why := refusal(runOp(t, op.Name, in, nil)); !strings.Contains(why, bad) {
				t.Errorf("%s %s=%s: want it refused, got %q", op.Name, f.Name, bad, why)
			}

			// RSA-4096 takes seconds, and keys-generate's Enum is what generateKey reads.
			if op.Name == "keys-generate" {
				continue
			}
			for _, v := range f.Enum {
				in := input(op.Name, f.Name)
				in.Set(f.Name, v)
				why := refusal(runOp(t, op.Name, in, nil))
				// A value may fail on the rest of the input (RS256 with a secret), never by name.
				if f.Kind == ciphertools.KindInt && why != "" || strings.Contains(why, strconv.Quote(v)) {
					t.Errorf("%s %s=%s is in the spec's Enum but refused: %s", op.Name, f.Name, v, why)
				}
			}
		}
	}
}

func TestRequiredFlags(t *testing.T) {
	input := fieldInputs(t)
	for _, op := range ciphertools.Ops() {
		for _, f := range op.Fields {
			in := input(op.Name, f.Name)
			if !f.Required {
				// password-hash's defaults run at full cost.
				if in = input(op.Name, ""); !in.Has(f.Name) || op.Name == "password-hash" {
					continue
				}
			}
			if _, err := runOp(t, op.Name, in, nil); err != nil {
				t.Errorf("%s: the test's input for %s fails on its own: %v", op.Name, f.Name, err)
				continue
			}
			in.Del(f.Name)
			_, err := runOp(t, op.Name, in, nil)
			switch {
			case f.Required && err == nil:
				t.Errorf("%s runs without %s, which its spec says is required", op.Name, f.Name)
			case !f.Required && err != nil:
				t.Errorf("%s fails without %s, which its spec says is optional: %v", op.Name, f.Name, err)
			}
		}
	}
}
