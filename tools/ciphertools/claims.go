package ciphertools

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"time"
)

// claimMeanings: registered claims (RFC 7519 §4.1), common OIDC ones and the vendor claims most access tokens carry.
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

// orderedObject reads a JSON object keeping key order, so the claims table matches what was pasted.
func orderedObject(data []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil {
		return nil, jsonError(err)
	}
	if d, ok := tok.(json.Delim); !ok || d != '{' {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, jsonError(err)
		}
		key, _ := kt.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, jsonError(err)
		}
		out = append(out, member{Key: key, Raw: raw})
	}
	if _, err := dec.Token(); err != nil { // closing brace
		return nil, jsonError(err)
	}
	if dec.More() {
		return nil, errors.New("trailing data after the JSON object")
	}
	return out, nil
}

// jsonError rewords encoding/json errors that name Go types or end in a bare "EOF".
func jsonError(err error) error {
	var te *json.UnmarshalTypeError
	switch {
	case errors.As(err, &te) && te.Field != "":
		return fmt.Errorf("%q must be %s, found a JSON %s", te.Field, jsonKind(te.Type), te.Value)
	case errors.As(err, &te):
		return fmt.Errorf("must be %s, found a JSON %s", jsonKind(te.Type), te.Value)
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return errors.New("the JSON ends before it is closed")
	}
	return err
}

func jsonKind(t reflect.Type) string {
	return cmp.Or(map[reflect.Kind]string{reflect.String: "a string", reflect.Slice: "an array", reflect.Array: "an array",
		reflect.Struct: "an object", reflect.Map: "an object", reflect.Bool: "true or false"}[t.Kind()], "a number")
}

// display is a table cell: strings unquoted, the rest compact JSON.
func display(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var b bytes.Buffer
	_ = json.Compact(&b, raw) // raw came from orderedObject, so it is valid
	return b.String()
}

// numericDate reads seconds since the epoch, fractions allowed (RFC 7519 §2); ok=false for anything else.
func numericDate(raw json.RawMessage) (time.Time, bool) {
	var f float64
	if json.Unmarshal(raw, &f) != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return time.Time{}, false
	}
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
	n, unit := s, "second"
	for _, u := range []struct {
		secs int64
		name string
	}{{60, "minute"}, {3600, "hour"}, {86400, "day"}, {86400 * 365, "year"}} {
		if s >= u.secs {
			n, unit = s/u.secs, u.name
		}
	}
	if n == 1 {
		return "1 " + unit
	}
	return fmt.Sprintf("%d %ss", n, unit)
}
