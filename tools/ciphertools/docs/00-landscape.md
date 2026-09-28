# Landscape — what already exists

Surveyed 2026-09-28: two passes, one over JWT/JOSE and token tools, one over the
hash / encode / cipher multitools. **Live** means the page was loaded during the
survey. **Recall** means it could not be loaded (JS-only or blocked), so the entry
is based on existing knowledge of the tool and should be taken as that.

## The tools

| Tool | What it is | Runs where | Best idea | Worst flaw |
|---|---|---|---|---|
| [jwt.io](https://www.jwt.io/) · live | The default JWT debugger | browser | Encoded and decoded side by side, both editable; a clear "verified / invalid" badge next to the key | A token decodes with no key, and the page has long let that read as "valid". Editing the payload silently re-signs it |
| [jwt.ms](https://jwt.ms/) · live | Microsoft's decoder | browser | A claims tab with a plain-English meaning per claim. Also works as an OIDC `redirect_uri`, reading the token from the fragment | Decode only, so a forged token looks exactly like a real one. Explanations are Entra-specific |
| [token.dev](https://token.dev/) · live | Encode/decode with generated keys | browser | Says outright that its demo keys are not for production | No human-readable `exp`/`iat`, and no JWK/PEM |
| [FusionAuth](https://fusionauth.io/dev-tools/jwt-decoder) · live | Decoder inside a small dev-tools family | browser | One key box that accepts a secret, a PEM or a JWK | A lead-gen page; HMAC and RSA only |
| [Dino Chiesa](https://dinochiesa.github.io/jwt/) · live | The most complete JWS + JWE tool | browser | A secret-encoding selector (UTF-8/hex/base64) and a warning when an HMAC key is shorter than the hash | Dense UI. Keys persist in localStorage by default, and tokens can be passed in the URL |
| [IT-Tools](https://it-tools.tech/) · live | Open-source Vue multitool | browser | Tiny single-purpose tools; hashes show **every algorithm at once**; TOTP shows the previous and next codes too | JWT parser can't verify. Its "encrypt text" is CryptoJS passphrase mode, which can't interoperate with anything else; RC4 offered without a warning |
| [CyberChef](https://gchq.github.io/CyberChef/) · recall | GCHQ's recipe engine | browser | An input/output charset on every field, and recipe chaining | Steep learning curve. Signs `alg: none` and encrypts with ECB and an all-zero IV without a word |
| [emn178 online-tools](https://emn178.github.io/online-tools/) · live | One page per hash algorithm | browser | A text / hex / base64 input selector on every hash | Hundreds of near-identical pages, ads, no compare-with-checksum |
| [8gwifi.org](https://8gwifi.org/) · live | Sprawling crypto playground | mostly server | Widest PKI coverage; its PEM parser auto-detects the object type | Keys and secrets are posted to a server. Huge nav full of near-duplicates |
| [devglan](https://www.devglan.com/online-tools/aes-encryption-decryption) · live | AES/RSA/bcrypt pages | server | Inline warnings: ECB is insecure, a missing IV means zeros | Plaintext and keys go to its server; the GCM output layout is undocumented |
| [bcrypt-generator.com](https://bcrypt-generator.com/) · live | bcrypt only | browser | A clear privacy statement; recommends cost 12 | Says nothing about bcrypt's **72-byte truncation** |
| [TunnelsUp hash analyzer](https://www.tunnelsup.com/hash-analyzer/) · live | Hash identifier | unknown | Shows the bit length and charset, not just a name | Gives one answer to an ambiguous input: 32 hex characters could be MD5, NTLM or MD4 |
| [hashes.com identifier](https://hashes.com/en/tools/hash_identifier) · recall | Hash identifier | server | Gives hashcat mode numbers, which is what practitioners actually use | Sends your hashes to a cracking service |
| [base64decode.org](https://www.base64decode.org/) · recall | Base64 | server by default | Charset selector and a decode-each-line mode | Silent on invalid input; ad-heavy |
| [SSLShopper decoder](https://www.sslshopper.com/certificate-decoder.html) · live | X.509 decoder | server | Prints the `openssl` one-liner so you can do it locally | One certificate only: no chain, no DER, no fingerprints |
| [totp.danhersam.com](https://totp.danhersam.com/) · live | TOTP generator | browser | Paste the secret and get the code; a countdown bar shows the period | The secret travels in the URL when shared; no SHA-256/512, no `otpauth://` |

## Findings that shape the plan

1. **Every tool people trust runs in the browser, and says so.** jwt.io, jwt.ms,
   FusionAuth, token.dev, IT-Tools, CyberChef and bcrypt-generator all lead with
   "your token never leaves this page". The server-side tools (8gwifi, devglan,
   base64decode's default mode) are exactly the ones a reviewer calls
   untrustworthy. This repo's architecture is server-side Go, so this is the one
   real product decision. See [`02-build-plan.md` §Decision](02-build-plan.md#decision-where-the-crypto-runs).
2. **"Decoded" vs "verified" is the category's signature bug.** Only jwt.io shows
   a verify badge at all, and even it lets an unverified token look fine. The
   biggest correctness win on offer is a page that is loud about **"signature
   not checked"**.
3. **Encoding is ambiguous everywhere and almost nobody surfaces it.** Is a
   secret UTF-8, hex or base64? Does the input end in a newline? CRLF or LF? The
   good tools (Dino Chiesa, CyberChef, emn178) put a selector on the field;
   the rest produce "wrong" hashes and HMACs that users can't explain. Showing
   **byte counts** plus an explicit input-encoding selector fixes most of it.
4. **Nobody combines "hash" with "compare".** File checksum verification is the
   commonest reason to open a hash page, and the surveyed tools make you compare
   64 hex characters by eye. Paste the expected value and the page should tell
   you *which algorithm* it matches.
5. **Unsafe defaults go unmentioned.** `alg: none`, ECB, zero IVs, RC4, bcrypt
   truncation, a short HMAC key. They're each a one-line warning, and almost no
   tool prints one.
