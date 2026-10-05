package mcptools

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/Landver/site-of-tools/tools/ciphertools"
)

// cipherTool is what one op's tool says to a model. Its schema is generated
// from the op's own field specs, so only these words are written by hand.
type cipherTool struct{ name, title, desc string }

const testMaterial = "Inputs and outputs pass through corpberry.com and the user's AI provider, so use test material only."

var cipherTools = map[string]cipherTool{
	"jwt-decode": {"cipher_jwt_decode", "Decode and verify a JWT",
		"Decode a JWT's header and claims, check exp and nbf against the current time (or now), and verify the signature when key is given: " +
			"the shared secret for HS*, or a PEM, JWK, JWKS or OpenSSH public key for RS*, PS*, ES* and EdDSA. " +
			"verification.state says whether the signature checked out, and carries the reason when the key can't be read; validity.state says whether the token is in date. " +
			"Without a key nothing is verified, since anyone can write a header and payload. Example: token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9…, key your-256-bit-secret."},
	"jwt-sign": {"cipher_jwt_sign", "Sign a JWT",
		"Sign a JWT with a shared secret (HS256, the default, HS384 or HS512) or a private key as PEM, JWK or JWKS (RS*, PS*, ES*, EdDSA), optionally adding iat and an exp lifetime. " +
			"payload and header are JSON text inside a string, and the claims are signed in the order written. " +
			"The result is the token with the breakdown cipher_jwt_decode gives. Example: key 0123456789abcdef0123456789abcdef, payload {\"sub\":\"42\"}, exp 1h."},
	"hash": {"cipher_hash", "Hash text or bytes",
		"Hash an input with every common algorithm at once (MD5, SHA-1, SHA-2, SHA-3, BLAKE2, Keccak-256, CRC32, Adler-32), each as hex and base64. " +
			"text is read as UTF-8 unless enc says hex or base64, which is how to hash binary data (up to about 750 KB here); " +
			"expected is compared with every digest and the result names the algorithm it matches. " +
			"A trailing newline, CRLF or BOM is flagged, the usual reason two hashes of the same text differ. Example: text abc, expected ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad."},
	"hmac": {"cipher_hmac", "HMAC and webhook signatures",
		"Compute HMAC-SHA256, SHA-512, SHA-1, MD5 and SHA-3 of text under key at once, or check a webhook signature: " +
			"expected is compared in constant time with every algorithm, bare or labelled (GitHub's sha256=…, a Stripe-Signature header). " +
			"For a webhook, text must be the raw request body byte for byte. With key_enc auto the key is read as text and, if expected doesn't match that way, as base64 and hex too, and the result says which reading matched. " +
			"Example: text {\"action\":\"opened\"}, key webhook-secret, expected sha256=…."},
	"password-hash": {"cipher_password_hash", "Hash a password",
		"Hash a password with bcrypt (the default), Argon2id, scrypt or PBKDF2; each algorithm reads only its own cost fields, bounded so one call stays cheap. " +
			"The result is the encoded hash a library would store, its parameters read back, and warnings for weak settings such as bcrypt below cost 10. " +
			"bcrypt refuses a password over 72 bytes instead of silently cutting it. Example: password correct horse battery staple, algo argon2id."},
	"password-verify": {"cipher_password_verify", "Check a password hash",
		"Read a stored password hash (bcrypt, Argon2, scrypt, PBKDF2 including Django's) and check a password against it. " +
			"state is match or no-match; unchecked when no password is given and the hash's algorithm, parameters and salt are only read; " +
			"unsupported for a crypt(3) format it names but can't verify; refused for parameters above this server's limits. Example: hash $2b$12$…, password hunter2."},
	"encrypt": {"cipher_encrypt", "Encrypt or decrypt",
		"Encrypt text (mode encrypt, the default) or decrypt data (mode decrypt) with AES-GCM (the default), ChaCha20-Poly1305 or AES-CBC, the key as hex, base64 or base64url. " +
			"Encrypting without key makes a random 32-byte key and returns it as generated_key, and without nonce a random one is used. " +
			"The result states its layout (nonce ‖ ciphertext ‖ tag) so other code can read it, and decrypting reads that combined form. Example: key 000102030405060708090a0b0c0d0e0f, text hello."},
	"keys-generate": {"cipher_keys_generate", "Generate a key pair",
		"Generate a test key pair: Ed25519 (the default), ECDSA on P-256, P-384 or P-521, or RSA of 2048, 3072 or 4096 bits. " +
			"The result has the private key as PKCS#8 PEM, JWK and OpenSSH, the public key as PEM, JWK and an OpenSSH line, and their fingerprints; " +
			"with passphrase the private key comes back only as encrypted OpenSSH. Example: type ec-p256, comment ci-deploy-test."},
	"keys-inspect": {"cipher_keys_inspect", "Inspect and convert keys",
		"Read up to 64 keys and convert each between formats: PEM (PKCS#8, PKCS#1, SEC 1, SPKI, OpenSSH, or a certificate's key), a JWK or JWKS, or OpenSSH public key lines. " +
			"Each comes back as PEM, JWK and OpenSSH, with its SPKI and OpenSSH SHA-256 fingerprints, its RFC 7638 JWK thumbprint, and whether it is private. " +
			"Example: key ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI… user@host."},
	"cert": {"cipher_cert", "Decode certificates",
		"Decode X.509 certificates and signing requests from PEM, or DER as base64 or hex: subject and SANs, validity, issuer, key, usages and SHA-256 fingerprints. " +
			"Several certificates are checked as a chain, for order and each signature; expiry, SHA-1 and CN-only certificates are flagged, " +
			"and key says which certificate a public or private key belongs to. now sets the time validity is judged at. Example: cert -----BEGIN CERTIFICATE-----…"},
	"totp": {"cipher_totp", "TOTP and HOTP codes",
		"Get the previous, current and next TOTP (or HOTP) code from a base32 secret or a whole otpauth:// URI, with the seconds left in the step. " +
			"code checks a code within one step either side, and label and issuer build an otpauth:// URI for an authenticator app. " +
			"now sets the time, to see what the codes were or will be. Example: secret JBSWY3DPEHPK3PXP, code 287082."},
	"random": {"cipher_random", "Random tokens, passwords, UUIDs",
		"Generate random values from a cryptographic source: tokens (kind token, the default) as hex, base64url, base64 or letters and digits; " +
			"passwords from the character sets chosen, with their exact entropy; or UUIDs, version 4 or 7. " +
			"count makes up to 20 tokens or passwords, or 100 UUIDs, at once. Example: kind password, length 24, sets [lower, upper, digits]."},
	"encode": {"cipher_encode", "Convert byte encodings",
		"Show the same bytes as UTF-8 text, hex, base64, base64url and base32: text is read per from (utf8 by default), and the base64 variant it was in is named. " +
			"A character that isn't valid in the encoding is pointed at by its offset. " +
			"Use it to see what a base64 or hex value holds, or to re-encode bytes. Example: text aGVsbG8gd29ybGQ=, from base64."},
	"basic": {"cipher_basic_auth", "HTTP Basic auth header",
		"Build an HTTP Basic auth header from user and password, or decode one: header takes a whole Authorization: Basic … line, a Basic … value or the bare base64. " +
			"mode is decode when header is given and build otherwise. The result shows the user and password with their bytes, and the header. " +
			"Example: user Aladdin, password open sesame."},
	"identify": {"cipher_identify", "Identify a string",
		"Say what a string could be: a hash type with its hashcat mode, a JWT or JWE, a PEM key or certificate, an SSH key, a bcrypt or Argon2 hash, " +
			"a UUID, an otpauth:// URI, a webhook signature, or base64, hex or base32 data. " +
			"candidates are ranked by confidence, each with the reason and the cipher.corpberry.com page that reads it. Example: text 5d41402abc4b2a76b9719d911017c592."},
}

// maxSafeInt is the largest integer every JSON parser reads exactly.
const maxSafeInt = 1<<53 - 1

// cipherSpecs is one tool per ciphertools op. An op without words here, or
// words for no op, stops the boot rather than ship a tool nobody described.
func cipherSpecs(d Deps) ([]toolSpec, error) {
	lim := d.CipherLimits
	ops := ciphertools.Ops()
	if len(ops) != len(cipherTools) {
		return nil, fmt.Errorf("%d cipher ops but %d cipher tool descriptions", len(ops), len(cipherTools))
	}
	specs := make([]toolSpec, 0, len(ops))
	for _, op := range ops {
		ct, ok := cipherTools[op.Name]
		if !ok {
			return nil, fmt.Errorf("cipher op %q has no tool description", op.Name)
		}
		s := toolSpec{
			toolset: "cipher",
			tool: &mcp.Tool{Name: ct.name, Title: ct.title, Description: ct.desc + " " + testMaterial,
				InputSchema: cipherSchema(op), Annotations: readOnly(false)},
			deadline: quickDeadline,
			limiter:  lim.Pure,
			narrow:   "Pass less input.",
			whole:    true,
			add:      handle(cipherRun(op)),
		}
		if op.Heavy {
			s.deadline, s.limiter, s.cap = heavyDeadline, lim.Heavy, lim.HeavyCap
			s.weight = func(raw json.RawMessage) int64 {
				var args map[string]any
				_ = json.Unmarshal(raw, &args) // arguments that don't decode fail validation next
				in, _ := cipherInput(op, args)
				return ciphertools.HeavyWeight(op.Name, in)
			}
		}
		specs = append(specs, s)
	}
	return specs, nil
}

func cipherRun(op ciphertools.Op) func(context.Context, *mcp.CallToolRequest, map[string]any) (any, error) {
	return func(_ context.Context, _ *mcp.CallToolRequest, args map[string]any) (any, error) {
		in, err := cipherInput(op, args)
		if err != nil {
			return nil, err
		}
		return ciphertools.Run(op, in)
	}
}

// cipherInput is the form the arguments would have posted: a list joined
// with commas, the rest as InputFromJSON reads a JSON body.
func cipherInput(op ciphertools.Op, args map[string]any) (ciphertools.Input, error) {
	for _, f := range op.Fields {
		list, ok := args[f.Name].([]any)
		if f.Kind != ciphertools.KindList || !ok {
			continue
		}
		parts := make([]string, len(list))
		for i, v := range list {
			parts[i] = fmt.Sprint(v)
		}
		args[f.Name] = strings.Join(parts, ",")
	}
	return ciphertools.InputFromJSON(args)
}

// cipherSchema is op's input schema, from its field specs. A JSON field stays
// a string: re-encoding a payload would reorder the claims it signs. A file
// field has no JSON form and is left out.
func cipherSchema(op ciphertools.Op) *jsonschema.Schema {
	s := &jsonschema.Schema{Type: "object", Properties: map[string]*jsonschema.Schema{},
		AdditionalProperties: &jsonschema.Schema{Not: &jsonschema.Schema{}}}
	for _, f := range op.Fields {
		p := &jsonschema.Schema{Description: f.Description}
		var def any = f.Default
		switch f.Kind {
		case ciphertools.KindFile:
			continue
		case ciphertools.KindString:
			p.Type = "string"
		case ciphertools.KindJSON:
			p.Type, p.ContentMediaType = "string", "application/json"
		case ciphertools.KindEnum:
			p.Type, p.Enum = "string", values(f.Enum, false)
		case ciphertools.KindList:
			p.Type, p.Items = "array", &jsonschema.Schema{Type: "string", Enum: values(f.Enum, false)}
			def = strings.Split(f.Default, ",")
		case ciphertools.KindBool:
			p.Type, def = "boolean", f.Default == "true"
		case ciphertools.KindInt:
			p.Type = "integer"
			if len(f.Enum) > 0 {
				p.Enum = values(f.Enum, true)
			}
			if f.Min != nil {
				p.Minimum = jsonschema.Ptr(float64(max(*f.Min, -maxSafeInt)))
			}
			if f.Max != nil {
				p.Maximum = jsonschema.Ptr(float64(min(*f.Max, maxSafeInt)))
			}
			def, _ = strconv.Atoi(f.Default)
		default:
			panic("cipher field " + op.Name + " " + f.Name + " has unknown kind " + string(f.Kind))
		}
		// The SDK fills a default in before the handler runs, so only the op's
		// own default may appear; one that depends on another field has none.
		if f.Default != "" {
			raw, err := json.Marshal(def)
			if err != nil {
				panic(err)
			}
			p.Default = raw
		}
		if f.Required {
			s.Required = append(s.Required, f.Name)
		}
		s.Properties[f.Name] = p
		s.PropertyOrder = append(s.PropertyOrder, f.Name)
	}
	return s
}

// values are a field's Enum as schema values: numbers for an int field.
func values(enum []string, ints bool) []any {
	out := make([]any, len(enum))
	for i, v := range enum {
		out[i] = v
		if n, err := strconv.Atoi(v); ints && err == nil {
			out[i] = n
		}
	}
	return out
}
