package ciphertools

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"time"
)

// claimMeanings: registered JWT claims (RFC 7519 §4.1), the common OIDC ones,
// and the handful of vendor claims that turn up in almost every access token.
// jwt.ms's claims tab is the prior art; this list is vendor-neutral on purpose.
var claimMeanings = map[string]string{
	"iss":                "Issuer: who minted the token",
	"sub":                "Subject: who the token is about, usually a user id",
	"aud":                "Audience: who the token is for; a verifier must find itself here",
	"exp":                "Expires at: reject the token after this time",
	"nbf":                "Not before: reject the token before this time",
	"iat":                "Issued at",
	"jti":                "Token id: unique per token, for replay detection",
	"azp":                "Authorized party: the client the token was issued to",
	"nonce":              "Nonce from the login request; binds the ID token to one sign-in",
	"auth_time":          "When the user actually authenticated",
	"acr":                "Authentication context class, e.g. how strong the login was",
	"amr":                "Authentication methods used, e.g. pwd, otp, mfa",
	"scope":              "OAuth scopes granted, space-separated",
	"scp":                "OAuth scopes granted (Microsoft / Okta spelling)",
	"client_id":          "OAuth client the token was issued to",
	"sid":                "Session id at the identity provider",
	"at_hash":            "Hash of the access token issued alongside this ID token",
	"c_hash":             "Hash of the authorization code issued alongside this ID token",
	"cnf":                "Confirmation: the key the holder must prove possession of",
	"email":              "Email address",
	"email_verified":     "Whether the provider verified the email",
	"name":               "Full name",
	"given_name":         "Given name",
	"family_name":        "Family name",
	"preferred_username": "Username the user goes by",
	"picture":            "Profile picture URL",
	"locale":             "Preferred locale",
	"roles":              "Roles granted",
	"groups":             "Groups the user belongs to",
	"tid":                "Tenant id (Microsoft Entra)",
	"oid":                "Object id of the user (Microsoft Entra)",
	"uti":                "Internal token id (Microsoft Entra)",
	"ver":                "Token format version",
	"typ":                "Media type of the token",
	"org_id":             "Organisation id",
}

// headerMeanings: JOSE header parameters (RFC 7515 §4.1, RFC 7516 §4.1).
var headerMeanings = map[string]string{
	"alg":  "Signature (or key-management) algorithm",
	"typ":  "Media type of the whole token, usually JWT",
	"cty":  "Media type of the payload; JWT here means a nested token",
	"kid":  "Key id: which of the issuer's keys signed this",
	"jku":  "URL of a JWKS holding the signing key",
	"jwk":  "The signing key itself, embedded",
	"x5u":  "URL of the signing certificate chain",
	"x5c":  "The signing certificate chain, embedded",
	"x5t":  "SHA-1 thumbprint of the signing certificate",
	"crit": "Extensions a verifier must understand, or reject the token",
	"enc":  "Content encryption algorithm (JWE)",
	"zip":  "Compression applied before encryption (JWE)",
	"b64":  "Whether the payload is base64url-encoded (RFC 7797)",
}

// member is one key of a JSON object, with its raw value, in document order.
type member struct {
	Key string
	Raw json.RawMessage
}

// orderedObject reads a JSON object keeping key order. encoding/json into a
// map sorts keys, and a claims table in a different order from the token is
// a table nobody can check against what they pasted.
func orderedObject(data []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, err
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		out = append(out, member{Key: key, Raw: raw})
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return nil, err
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON object")
	}
	return out, nil
}

// display renders a raw JSON value for a table cell: strings unquoted, the rest
// compact JSON.
func display(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b bytes.Buffer
	if json.Compact(&b, raw) == nil {
		return b.String()
	}
	return string(raw)
}

// numericDate reads a NumericDate (RFC 7519 §2): seconds since the epoch,
// fractions allowed. ok=false for anything else, including the strings sloppy
// issuers emit — shown, never crashed on.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	var f float64
	if json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return time.Time{}, false
	}
	// Millisecond timestamps are the classic mistake; flagged by the caller,
	// still converted literally here.
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
}

// relative: "in 5 minutes" / "3 hours ago".
func relative(t, now time.Time) string {
	d := t.Sub(now)
	if d >= 0 {
		return "in " + humanDuration(d)
	}
	return humanDuration(-d) + " ago"
}

func humanDuration(d time.Duration) string {
	s := int64(d.Round(time.Second) / time.Second)
	unit := func(n int64, w string) string {
		if n == 1 {
			return "1 " + w
		}
		return fmt.Sprintf("%d %ss", n, w)
	}
	switch {
	case s < 60:
		return unit(s, "second")
	case s < 3600:
		return unit(s/60, "minute")
	case s < 86400:
		return unit(s/3600, "hour")
	case s < 86400*365:
		return unit(s/86400, "day")
	}
	return unit(s/(86400*365), "year")
}
