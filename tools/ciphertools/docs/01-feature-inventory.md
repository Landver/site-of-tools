# Feature inventory — the menu, and what ships

Every feature seen across the [surveyed tools](00-landscape.md), grouped, with
how many of them had it (**n**). The bar is the same one linktools used: a site of
tools, so a useful and cheap feature earns its place without having to be a
differentiator. The cut is at the end, with a reason for each item.

**Bold** marks the feature where this suite does better than what was surveyed.

## C1. JWT — `/` (the flagship)

| Feature | n | Ship |
|---|---|---|
| Decode header / payload / signature, no key needed | 8 | yes |
| Verify HS256/384/512 with a shared secret | 6 | yes |
| Verify RS/PS/ES/EdDSA with a public key as PEM or JWK | 5 | yes, and a JWKS picks by `kid` |
| Sign: header + payload JSON + key → token | 5 | yes |
| Per-claim explanation table (registered + common OIDC claims) | 3 | yes |
| `exp` / `iat` / `nbf` as dates, with an "expired 3 min ago" status | 3 | yes |
| Secret-encoding selector (UTF-8 / hex / base64 / base64url) | 3 | yes |
| **A "signature not checked" state that is as loud as "invalid"** | 0 | yes |
| **Algorithm bound to the key type, so there's no alg confusion; `alg: none` refused** | 1 | yes |
| Warnings: HMAC key shorter than the hash, no `exp`, very long lifetime, `jku`/`x5u`/`jwk` headers | 1 | yes |
| Expiry presets when signing (auto `iat`, `exp` = +15m / 1h / 1d) | 1 | yes |
| JWE (5 segments) recognised: header shown, body stated as encrypted | 1 | yes, detect only |

## C2. Hash — `/hash`

| Feature | n | Ship |
|---|---|---|
| Every algorithm at once, copy buttons: MD5, SHA-1, SHA-224/256/384/512, SHA-512/256, SHA3-256/512 | 4 | yes |
| BLAKE2b/2s, Keccak-256 (Ethereum; labelled distinct from SHA3-256) | 2 | yes |
| CRC32, CRC32C, Adler-32 | 2 | yes |
| Input as UTF-8 text / hex bytes / base64 bytes | 2 | yes |
| Output as hex and base64 | 2 | yes |
| File hashing | 3 | yes, size-capped upload |
| **Paste an expected checksum, and the page names the algorithm it matches** | 0 | yes |
| **Byte count, plus a note when the input ends in a newline or holds CRLF** | 0 | yes |

## C3. HMAC — `/hmac`

| Feature | n | Ship |
|---|---|---|
| HMAC-MD5/SHA-1/SHA-224/256/384/512/SHA3-256/512, all at once | 5 | yes |
| Key as text / hex / base64 | 5 | yes |
| **Verify: paste an expected MAC, get a constant-time match plus the algorithm** | 1 | yes |

Webhook signatures (Stripe, GitHub, Slack) are the everyday use. They're HMAC-SHA256
over the raw body, so this is the page for "why doesn't my signature match".

## C4. Password hashing — `/password`

| Feature | n | Ship |
|---|---|---|
| bcrypt hash (cost) + verify | 6 | yes |
| Argon2id / scrypt / PBKDF2, hash + verify, as PHC/MCF strings | 4 | yes |
| **Parse a pasted hash: algorithm, variant, parameters, salt** | 0 | yes |
| **Warn on bcrypt's 72-byte truncation, low cost, and weak parameters** | 0 | yes |
| Time taken for the chosen cost | 0 | yes |

## C5. Encrypt — `/encrypt`

| Feature | n | Ship |
|---|---|---|
| AES-GCM encrypt / decrypt, explicit key, random nonce | 4 | yes |
| ChaCha20-Poly1305 | 3 | yes |
| AES-CBC with PKCS#7, for interop with legacy systems | 4 | yes, flagged as unauthenticated |
| **The output layout stated (`nonce ‖ ciphertext ‖ tag`) so it interoperates** | 0 | yes |
| Passphrase mode (CryptoJS / `openssl enc` style) | 1 | no — see the cut |

## C6. Keys — `/keys`

| Feature | n | Ship |
|---|---|---|
| Generate RSA 2048/3072/4096, ECDSA P-256/384/521, Ed25519 | 5 | yes, labelled "for testing" |
| Output as PEM (PKCS#8 / SPKI), JWK, OpenSSH public key | 4 | yes |
| **OpenSSH private key (`ssh-keygen` format), with comment and optional passphrase** | 0 | yes, added after the owner asked for SSH key pairs |
| Inspect a pasted key: PEM (PKCS#1 / PKCS#8 / SPKI / SEC1) or JWK | 2 | yes |
| JWK ⇄ PEM, and the public key derived from a private one | 2 | yes |
| Fingerprints (SPKI SHA-256, OpenSSH `SHA256:`), JWK thumbprint (RFC 7638) | 0 | yes |

## C7. Certificates — `/cert`

| Feature | n | Ship |
|---|---|---|
| Decode X.509: subject, issuer, SANs, validity, key, signature algorithm | 3 | yes |
| Fingerprints (SHA-256 and SHA-1 over the DER bytes) | 1 | yes |
| CSR decode | 2 | yes |
| **Chains: several PEM blocks, order checked, each link verified to the next** | 0 | yes |
| DER / base64 input as well as PEM | 0 | yes |
| Does this key match this certificate? | 1 | yes |
| The equivalent `openssl` command | 1 | yes |

## C8. TOTP — `/totp`

| Feature | n | Ship |
|---|---|---|
| Base32 secret → code, digits, period, countdown | 4 | yes |
| SHA-1 / SHA-256 / SHA-512 | 2 | yes, with a note that Google Authenticator ignores them |
| Previous / current / next code (for clock skew) | 1 | yes |
| `otpauth://` URI parse + build | 1 | yes |
| Check a code against the secret (±1 step) | 0 | yes |
| HOTP (counter) | 2 | yes, same code path |

## C9. Random — `/random`

| Feature | n | Ship |
|---|---|---|
| Tokens / secrets: N bytes as hex, base64url, alphanumeric | 3 | yes |
| Passwords: length, character sets, drop ambiguous characters, entropy in bits | 3 | yes |
| UUID v4 / v7, in bulk | 3 | yes, with a note that v7 embeds its creation time |

## C10. Encode — `/encode`

| Feature | n | Ship |
|---|---|---|
| Bytes between UTF-8 text / hex / base64 / base64url / base32 | 4 | yes |
| Say which base64 variant was seen, and point at the character that broke it | 0 | yes |
| Show binary that isn't valid UTF-8 as hex, rather than mojibake | 0 | yes |
| HTTP Basic auth header, build + decode | 1 | yes |

Percent-encoding and HTML entities already live at
[link.corpberry.com/encode](../../linktools/docs/01-feature-inventory.md); this
page links there instead of repeating them.

## C11. Identify — `/identify`

| Feature | n | Ship |
|---|---|---|
| Hash-type identification: length, charset, `$`-prefix, hashcat mode | 3 | yes |
| **Ranked candidates, never one verdict** | 0 | yes |
| **Any pasted thing: JWT, JWE, PEM block, PHC string, UUID, `otpauth://`, base64, hex, with a link to the page that handles it** | 1 | yes |

## Cut, with reasons

| Feature | n | Why not |
|---|---|---|
| Passphrase text encryption (CryptoJS / OpenSSL `Salted__`) | 1 | EVP_BytesToKey is an MD5 KDF. It's the interop trap IT-Tools fell into, and the honest version is "derive a key on `/password`, encrypt on `/encrypt`" |
| JWE encrypt / decrypt | 1 | One tool does it well; niche. Detection only |
| Verify against a JWKS **URL** | 1 | Needs outbound fetch through the egress gate. Pasting the JWKS covers the need |
| PASETO | 1 | Low demand |
| QR codes for `otpauth://` | 1 | No stdlib encoder, and a new module for one image isn't worth it. The URI is shown instead |
| BLAKE3, xxHash, RIPEMD-160 | 2 | BLAKE3/xxHash are third-party modules; RIPEMD-160 is deprecated in `x/crypto` |
| Base58 / Base85 | 2 | Niche (Bitcoin / Adobe) |
| Password strength / crack time | 1 | Doing it well means zxcvbn's dictionaries. A number from a character-class formula is worse than nothing |
| UUID v1/v3/v5, ULID | 3 | v4 + v7 cover real use |
| Self-signed CA, keystores, OCSP, PGP, SAML | 1 | PKI management, not a scratchpad |
| Classical ciphers | 1 | Different audience |
| ECB mode, RC4, DES/3DES | — | Won't offer broken primitives, even with a warning |
| HKDF | 1 | Cheap, but nobody asked. First in line for a v2 |
