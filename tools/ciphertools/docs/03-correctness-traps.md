# Correctness traps — the test checklist

Collected from the survey. Each of these is a real mistake, either one a surveyed
tool makes or one its documentation warns about. Every line should end up as a
test case in `tests/`.

## Everywhere

- **Text vs bytes.** `abc` as UTF-8, `616263` as hex and `YWJj` as base64 are the
  same three bytes, so all three must hash identically. Input encoding is always
  explicit, and defaults to UTF-8.
- **Trailing newline.** `echo foo | md5sum` hashes `foo\n`. Show the byte count,
  and say when the input ends in `\n` or contains `\r\n`, because that is where
  "your MD5 is wrong" comes from.
- **Don't normalise silently.** No Unicode NFC/NFD folding, no trimming of the
  *data*. Trimming a pasted *token* (`Bearer `, quotes, whitespace) is fine,
  because a token can't contain those characters.
- **Binary output.** Decoded bytes that aren't valid UTF-8 get shown as hex,
  never forced into a string.
- **Invalid input says where.** base64 and hex errors name the offending offset.
  A silent empty result is not an answer.
- **Hex compare.** Case and whitespace are normalised before comparing
  checksums, and MAC comparison uses `hmac.Equal` / `subtle.ConstantTimeCompare`.
- **Randomness is `crypto/rand` only.** Map bytes onto a charset by rejection
  sampling, not modulo. `math/rand` must not be imported anywhere in the package.

## JWT

- Segments are **base64url without padding**. Decode must accept missing `=`;
  encode must never emit `+`, `/` or `=`.
- **Decode ≠ verify.** With no key, the state is "signature not checked", shown as
  prominently as "invalid". Never green without a key.
- **`alg: none`, in any case (`None`, `NONE`), never verifies**, and the signer
  refuses it.
- **Algorithm confusion.** The key's type picks the permitted algorithms. The
  header's `alg` only has to be *consistent* with them. An RSA public key PEM
  offered as an HS256 secret is refused, not HMAC'd.
- The HMAC secret's encoding (UTF-8 / hex / base64 / base64url) is explicit,
  or, by default, detected: a token doesn't record it, and one string can be
  valid text and valid base64 at once, so the verifier tries each reading and
  names the one that matched. With an explicit choice that fails, it still says
  which reading would have matched. jwt.io's "secret base64 encoded" checkbox is
  the classic source of "invalid signature".
- Editing the payload invalidates the signature. Don't silently re-sign; say the
  original no longer matches.
- Re-serialising JSON changes bytes: a re-signed token won't match the original,
  even with identical claims. Verify always runs over the **original** segments.
- **ECDSA signatures are raw `r ‖ s`** (32/48/66-byte halves for ES256/384/512),
  not the DER that Go's `ecdsa.SignASN1` produces. Convert in both directions.
- **ES512 is P-521**, with 66-byte coordinates in the JWK.
- **PS\*** uses a PSS salt length equal to the hash length.
- `exp`/`nbf`/`iat` are **seconds**, may be floats, may be missing, and in sloppy
  tokens may even be strings. Display, don't crash. Say how much clock-skew
  leeway was applied.
- `aud` is a string or an array.
- Five segments means JWE: detect it, don't error.
- Unknown `crit` headers mean the token must be rejected.

## Hash / HMAC

- **Keccak-256 ≠ SHA3-256.** Different padding. Label both, and say which one
  Ethereum uses (Keccak).
- An HMAC key longer than the block size is pre-hashed. That's correct per RFC 2104;
  don't "fix" it.
- An empty key is valid HMAC. Allow it, and warn.

## Passwords

- **bcrypt truncates at 72 bytes** (UTF-8 bytes, not characters). Warn when the
  input exceeds that. Go's `bcrypt` returns an error rather than truncating, so
  say so instead of showing a 500.
- `$2a$` / `$2b$` / `$2y$` verify alike; name the variant.
- Parameters are part of the output (PHC `$argon2id$v=19$m=…,t=…,p=…$salt$hash`),
  and verify reads them back from the string.
- **Server CPU is the attack surface.** Cap the parameters: bcrypt cost ≤ 14,
  Argon2 m ≤ 64 MiB and t ≤ 10, scrypt N ≤ 2¹⁷, PBKDF2 ≤ 2,000,000 iterations.
  Put the page on a strict rate limit.

## Encrypt

- Key length is exactly 16/24/32 bytes after decoding. **Never pad or truncate**
  a string into a key.
- A GCM nonce is 12 bytes; generate it randomly by default. Never default to
  zeros. A user-supplied nonce carries a reuse warning.
- CBC gets a random 16-byte IV, PKCS#7, and an "unauthenticated, malleable" flag.
  A padding error on decrypt reads "wrong key or corrupted data", not a Go error.
- Output layout is stated and stable: `nonce ‖ ciphertext ‖ tag` for AEADs,
  `iv ‖ ciphertext` for CBC.

## Keys / certificates

- PEM flavours: `RSA PRIVATE KEY` (PKCS#1), `PRIVATE KEY` (PKCS#8), `PUBLIC KEY`
  (SPKI), `EC PRIVATE KEY` (SEC1), `RSA PUBLIC KEY`. Accept all of them and
  say which was seen. Encrypted PEM gets a clear refusal.
- **Converting a private JWK to public emits no private members** (`d`, `p`, `q`,
  `dp`, `dq`, `qi`).
- JWK integers are base64url, big-endian, with leading zeros stripped. EC
  coordinates are the exception: they're fixed-length.
- Certificate fingerprints hash the **DER bytes**, not the PEM text.
- SANs matter; CN is legacy. Show SANs first.
- Several PEM blocks means a chain; check the order and each signature link.

## TOTP

- Base32 secrets arrive lowercase, space-separated and unpadded. Normalise
  before decoding.
- Counter = `floor(unix / period)` as 8 bytes big-endian. Dynamic truncation
  masks the top bit.
- Google Authenticator ignores non-SHA-1 algorithms and digit counts other than 6.
  Say so when someone picks them.

## Identify

- 32 hex characters is MD5, NTLM, MD4 **or** LM. Return ranked candidates with
  hashcat modes, never a single verdict.
