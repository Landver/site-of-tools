# Link wrapper formats — what unwraps with no network

**Desk research 2026-09-25.** Evidence base for
[A16 Known-wrapper unwrap](../01-feature-inventory.md#a16-known-wrapper-unwrap).

The claim A16 rests on is that the common corporate and social wrappers carry
the real target *inside the rewritten URL*, so recovering it is string work.
That claim holds for 16 of the 19 wrappers below. The three it does not hold for
are opaque shorteners, and they belong to A6 Trace, not here.

Every algorithm marked **executed** below was run locally against the stated
input before this was written. No wrapped URL belonging to a person was fetched;
the one real sample used (urldefense v3) is a public bug-report artefact for an
association's newsletter anchor, and it was decoded offline, never opened.

---

## 1. Summary table

`✔` = the target is recoverable from the string alone.

| Wrapper | Host pattern | Target held in | Encoding | Offline | Conf. |
|---|---|---|---|---|---|
| Microsoft Safe Links | `*.safelinks.protection.outlook.com`, `*.safelinks.protection.office365.us`, `*.safelinks.protection.outlook.cn` | `?url=` | percent, **usually once** | ✔ | high |
| Proofpoint v1 | `urldefense.proofpoint.com/v1/url` | `?u=` (up to `&k=`) | percent + HTML entities | ✔ | high |
| Proofpoint v2 | `urldefense.proofpoint.com/v2/url` | `?u=` (up to `&d=`/`&c=`) | `-`→`%`, `_`→`/`, then percent | ✔ | high |
| Proofpoint v3 | `urldefense.com/v3/__…__;…!…$` | path, between `__` … `__` | `*` tokens + base64url table | ✔ | high |
| Google redirect | `*.google.<tld>/url` | `?q=` or `?url=` | percent | ✔ | high |
| Google Ads | `*.google.<tld>`, `googleadservices.com` | `?adurl=` | percent | ✔ | medium |
| Google AMP viewer | `*.google.<tld>/amp/s/<host>/<path>` | path tail | none (`/s/` ⇒ https) | ✔ | medium |
| Facebook link shim | `l.facebook.com`, `lm.facebook.com`, `l.messenger.com` | `?u=` | percent, **or none** | ✔ | high |
| Instagram | `l.instagram.com` | `?u=` | percent | ✔ | medium |
| LinkedIn interstitial | `www.linkedin.com/redir/redirect` | `?url=` | percent | ✔ | medium |
| Tumblr | `t.umblr.com/redirect` | `?z=` | percent | ✔ | high |
| Reddit | `out.reddit.com`, `click.redditmail.com` | `?url=` | percent | ✔ | high |
| Steam | `steamcommunity.com/linkfilter/` | `?url=` **or** `?u=` | percent | ✔ | medium |
| href.li | `href.li/?<target>` | the whole query string | none | ✔ | high |
| VK | `vk.com/away.php` | `?to=` | percent | ✔ | high |
| YouTube | `*.youtube.com/redirect` | `?q=` | percent | ✔ | high |
| Slack | `slack-redir.net/link` | `?url=` | percent | ✔ | medium |
| Barracuda | `linkprotect.cudasvc.com/url` | `?a=` | percent | ✔ | high |
| Cisco Secure Email | `secure-web.cisco.com/<token>/<target>` | path tail | percent | ✔ | high |
| Mimecast | `protect-*.mimecast.com/s/<token>` | `?domain=` — **host only** | none | partial | medium |
| **t.co** | `t.co/<id>` | — | — | ✘ | high |
| **lnkd.in** | `lnkd.in/<id>` | — | — | ✘ | high |
| **bit.ly and peers** | `bit.ly`, `ow.ly`, `buff.ly`, … | — | — | ✘ | high |

---

## 2. The line that matters

**Offline (A16).** The wrapper *contains* the target. Decoding is
`url.QueryUnescape` on a named parameter, or a documented substitution. No
socket, no SSRF surface, no rate limit, no way for the destination to learn the
link was inspected. Everything above the `t.co` row.

**Needs a fetch (A6 Trace, not A16).** `t.co`, `lnkd.in`, `bit.ly` and the rest
of the generic shorteners store the mapping **server-side**; the path is an
opaque database key. Twitter's own path is an HTTP 301 from its servers, and the
documented way to resolve one is a `HEAD` and a redirect follow
([redirectsniffer](https://redirectsniffer.com/expand-tco-link),
[Twitter developer docs](https://developer.twitter.com/en/docs/twitter-api/enterprise/enrichments/overview/expanded-and-enhanced-urls)).
No amount of string work recovers those. Putting them in A16's table would be a
lie the UI then has to apologise for.

**Mimecast sits between the two and should be labelled as such.** The `/s/<token>`
part is opaque. The optional `?domain=` suffix names the destination *domain* and
nothing else, and only when the admin enabled **Display URL Destination Domain**
in the URL Protect definition
([Mimecast support](https://mimecastsupport.zendesk.com/hc/en-us/articles/34000769379219-Targeted-Threat-Protection-URL-Protect-Embedded-Links)).
So the honest output is "this goes to `example.com`, path unknown", not a URL.

---

## 3. Microsoft Safe Links

Microsoft documents the host and nothing else:

> Scanned URLs are rewritten or *wrapped* using the Microsoft standard URL
> prefix: `https://<DataCenterLocation>.safelinks.protection.outlook.com`

— [Microsoft Learn, Safe Links overview](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)

`<DataCenterLocation>` is `nam01`…, `eur0x`, `apc0x`, `gcc02`, and so on. Two
sibling clouds exist: `safelinks.protection.office365.us` (GCC High / DoD) and
`safelinks.protection.outlook.cn`. Match the suffix, not the prefix.

Four parameters, one of which is documented:

| Param | Contents |
|---|---|
| `url` | the original target, percent-encoded |
| `data` | tenant/message routing metadata — **undocumented** |
| `sdata` | integrity signature — **undocumented** |
| `reserved` | always `0` in observation — **undocumented** |

Microsoft has never answered what `data`/`sdata` carry; the question sat
[unanswered on their own community forum](https://techcommunity.microsoft.com/t5/security-compliance-and-identity/data-sdata-and-reserved-parameters-in-office-atp-safelinks/td-p/1637050).
Treat all three as opaque and **drop them** — do not try to surface a "sender"
from `data`.

### Worked example — executed

Synthetic. Target deliberately contains its own `%20`:

```
target   https://example.com/docs?id=7&q=a%20b
wrapped  https://nam01.safelinks.protection.outlook.com/?url=https%3A%2F%2Fexample.com%2Fdocs%3Fid%3D7%26q%3Da%2520b&data=05%7C01%7C…&sdata=SYNTHETIC&reserved=0
```

1. Take `url` **without decoding the query first** — the value contains `%26`,
   so splitting on a decoded string merges it into the wrapper's own params.
2. `QueryUnescape` **once** → `https://example.com/docs?id=7&q=a%20b`. Done.

**Decoding twice gives `q=a b` — a different URL.** The target's own `%20`
became `%2520` purely because Safe Links encoded it, and a second pass eats it.
This is the single most common bug in the hobby decoders.

### When there really are two layers

Safe Links genuinely double-encodes when it wraps something already wrapped, or
when the mailer encoded the anchor before Defender saw it. Then the value starts
`https%253A%252F%252F`. Verified ladder:

```
url=  https%253A%252F%252Fexample.com%252Fdocs%253Fid%253D7%2526q%253Da%252520b
 d1   https%3A%2F%2Fexample.com%2Fdocs%3Fid%3D7%26q%3Da%2520b
 d2   https://example.com/docs?id=7&q=a%20b
```

The rule that distinguishes the two cases: **decode once, then stop unless the
result is still not an absolute URL.** `https://…` ⇒ stop. `https%3A//…` ⇒ go
again. Cap the loop and record each rung as a `Layer` ([03 §2](../03-architecture.md#2-domain-types)).

One more: pulled from raw HTML source, the separators are `&amp;`. Unescape
entities before parsing the query, or `sdata` swallows the rest.

---

## 4. Proofpoint urldefense

Proofpoint ships a [URL Decoder API](https://help.proofpoint.com/Threat_Insight_Dashboard/API_Documentation/URL_Decoder_API)
and presents it as *the* way to decode — but the formats are self-contained and
the company's own engineer published the offline decoder, which every
third-party implementation is a port of
([Proofpoint_URLDefenseDecoder_3.py, credited to Eric Van Cleve of Proofpoint](https://gist.github.com/PolarBearGod/28a3357b1314bca873bf681fa728d116);
[cardi/proofpoint-url-decoder](https://github.com/cardi/proofpoint-url-decoder/blob/main/decode.py)).
**No API key is needed to unwrap one.**

### v1 and v2

Both put the target in `u`. The regexes capture up to the next known parameter,
because the target may contain `&`:

```
v1   u=(.+?)&k=
v2   u=(.+?)&[dc]=
```

v1: percent-decode, then HTML-unescape.
v2: substitute **`-` → `%` and `_` → `/`**, then percent-decode, then
HTML-unescape. Literal `-` and `_` in the original survive because they were
encoded first: `-` → `%2D` → `-2D`, `_` → `%5F` → `-5F`.

#### Worked example — executed

```
wrapped  https://urldefense.proofpoint.com/v2/url?u=https-3A__example.com_a-3Fb-3D1-26c-3D2&d=DwMFaQ&c=AAAA&r=BBBB&m=CCCC&s=DDDD&e=
  s/-/%/  https%3A__example.com_a%3Fb%3D1%26c%3D2
  s|_|/|  https%3A//example.com/a%3Fb%3D1%26c%3D2
  unquote https://example.com/a?b=1&c=2
```

### v3 — the one that is non-obvious

Shape:

```
https://urldefense.com/v3/__<munged target>__;<base64url>!!<click-tracking>$
```

The munged target is the real URL with some characters removed and replaced by
`*` tokens. Those removed characters, concatenated in order, are the payload of
the base64url string after `__;`. Everything after `!!` is tracking and is
discarded.

Token grammar:

- `*` — consume **one** character from the replacement string.
- `**X` — consume a **run**. `X` indexes `A-Za-z0-9-_` (standard base64url
  alphabet); `A` = 2, `B` = 3, `C` = 4 … so a run is always ≥ 2.

Steps:

1. Match `v3/__(.+?)__;(.*?)!`.
2. Percent-decode the munged target — **before** substitution, not after.
3. Append `==` to the replacement string and **base64url**-decode it (`-`/`_`
   alphabet, not `+`/`/`). The over-padding is harmless and covers all three
   length cases in one line.
4. Walk the munged target left to right replacing each token, consuming the
   replacement string with a single moving cursor.

**You never need to know which characters Proofpoint chooses to munge.** The
replacement string tells you. That is what makes the format decodable at all,
and it is worth writing down because every attempt to reverse-engineer the
"special character set" is wasted effort.

#### Worked example — executed, real sample

From [cardi/proofpoint-url-decoder issue #4](https://github.com/cardi/proofpoint-url-decoder/issues/4):

```
wrapped  https://urldefense.com/v3/__https://contact.framasoft.org/*newsletter__;Iw!!LIr3w8kk_Xxm!6BNqFLJ13q7N5_lf3XQFlmTtgY5CkKjhfcIn4ybAhA1_gx_y07jmQ4uvR2QZ$
  "Iw" + "==" → base64url → "#"
  one "*", one replacement char
decoded  https://contact.framasoft.org/#newsletter
```

#### Worked examples — executed, synthetic

Two single tokens:

```
replacement  "#&"  → base64url → "IyY"
wrapped      https://urldefense.com/v3/__https://example.com/report*section-2*x=1__;IyY!!SYNTHETIC$
decoded      https://example.com/report#section-2&x=1
```

A run of three:

```
replacement  "#&#" → base64url → "IyYj"   run token **B = 3
wrapped      https://urldefense.com/v3/__https://example.com/a**Bb__;IyYj!!SYNTHETIC$
decoded      https://example.com/a#&#b
```

An unmunged URL has an **empty** replacement string — `__;!!` with nothing
between. Proofpoint's own sample set includes this shape
(`…/v3/__http://www.example.com__;!!foo!bar$`), so the regex must accept
zero-length and the base64 step must tolerate `""`.

#### The single-slash edge case

Some v3 rewrites collapse the scheme's `//` to a single `/`, and decoders that
do not repair it emit `https:/host/…` or, worse, re-anchor it against the
wrapper host — a reported real failure
([Rapid7 plugin thread](https://discuss.rapid7.com/t/proofpoint-url-defense-not-decoding-correctly/484)).
Proofpoint's later decoder revisions carry a `v3_single_slash` repair,
`^([a-z0-9+.-]+:/)([^/].+)$` → insert the missing slash, applied before
substitution. Not present in every third-party port; **confidence medium**, but
cheap to implement and cheap to test.

---

## 5. Google

Three distinct shapes, all in the ClearURLs catalog
([rules2.clearurls.xyz/data.minify.json](https://rules2.clearurls.xyz/data.minify.json),
the same artefact measured in [tracking-parameter-reference.md](tracking-parameter-reference.md)):

```
/url\?.*?(?:url|q)=(https?[^&]+)
/.*?adurl=([^&]+)
/amp/s/([^&]+)
```

- **`/url?q=`** is the old search/Gmail form; **`/url?url=…&usg=…`** is the
  newer one. `sa` and `usg` are a signature pair: with a valid `usg` Google
  redirects silently, without it you get an interstitial
  ([SANS ISC](https://isc.sans.edu/diary/How+Malware+Campaigns+Employ+Google+Redirects+and+Analytics/19843)).
  For unwrapping, `usg` is noise — drop it.
- Accept **either** parameter, and note that the regex anchors on `https?` so a
  relative or non-http `q` is correctly ignored. That guard is worth keeping.
- **AMP viewer**: `google.com/amp/s/example.com/page` → `https://example.com/page`.
  `/s/` means https; without it, http. Reconstruction, not decoding, so mark it
  as such in the UI.
- **`googleweblight`: dead.** Google [retired Web Light](https://searchengineland.com/google-search-retires-web-light-googles-method-to-serve-faster-lighter-pages-to-people-390389)
  and the `googleweblight` user agent along with it. Do not ship a rule for it.

```
wrapped  https://www.google.com/url?q=https%3A%2F%2Fexample.org%2Fpage%3Fa%3D1%26b%3D2&sa=D&usg=SYNTHETIC
decoded  https://example.org/page?a=1&b=2
```

---

## 6. Facebook, Instagram, Messenger

Meta's link shim wraps every outbound link so it can be checked against
reputation feeds at click time
([Engineering at Meta](https://engineering.fb.com/2012/09/14/security/a-faster-better-link-shim/)).
Hosts: `l.facebook.com`, `lm.facebook.com` (mobile), `l.messenger.com`,
`l.instagram.com`. Target in `u`; `h` is a per-destination hash.

**Both encodings occur in the wild.** ClearURLs only matches the encoded form —
`u=(https?%3A%2F%2F[^&]*)` — while EFF's write-up of the same feature shows the
raw form, `l.php?u=https://eff.org/pb&h=ATPY93…`
([EFF](https://www.eff.org/de/deeplinks/2018/05/privacy-badger-rolls-out-new-ways-fight-facebook-tracking)).
Handle both.

**The trap, and it is a live one.** A greedy capture that does not stop at `&`
appends the shim's own `h` to the destination — the exact bug filed against one
unwrapper as "[DNR rules append trailing params (h=) to the unwrapped
destination](https://github.com/yocreoquesi/muga/issues/1449)":

```
wrapped  https://l.facebook.com/l.php?u=https://example.org/page?a=1&b=2&h=AT0SYNTHETIC
naive    https://example.org/page?a=1&b=2&h=AT0SYNTHETIC     ← wrong
correct  https://example.org/page?a=1&b=2
```

Splitting the wrapper's query into pairs *first* and reading the `u` pair makes
this impossible, which is an argument for reusing A1's parser rather than
writing regexes.

---

## 7. LinkedIn

Two mechanisms, and the distinction is the finding.

- **`lnkd.in/<id>` is not decodable offline.** It is an opaque shortener keyed
  server-side, same class as `t.co` and `bit.ly`. A16 must not claim it.
  [02 §build-fit](../02-build-fit.md) already says so; this report confirms it.
- **`www.linkedin.com/redir/redirect?url=<target>&urlhash=<token>`** is the
  in-product interstitial and *is* offline-decodable from `url`. `urlhash` is a
  validation token. Worth knowing: the interstitial itself only renders for a
  logged-in session with a matching `Referer` and otherwise 404s
  ([ClearURLs/Addon #194](https://github.com/ClearURLs/Addon/issues/194)), which
  is a second reason to unwrap it offline rather than trace it.

Confidence medium: the parameter name is consistent across sources, but LinkedIn
publishes nothing.

---

## 8. The rest

| Wrapper | Shape | Note |
|---|---|---|
| Tumblr | `t.umblr.com/redirect?z=<pct>&t=<hmac>` | `z` is the target, `t` an HMAC. ClearURLs `redirect\?z=([^&]+)` |
| Reddit | `out.reddit.com/…?url=<pct>&token=…`, `click.redditmail.com/…?url=` | two hosts, one parameter |
| Steam | `steamcommunity.com/linkfilter/?url=<pct>` | **format moved.** `?u=` is reported in community posts from Aug–Sep 2025; ClearURLs still carries `?url=`. Ship both, mark `?u=` unverified |
| href.li | `href.li/?https://example.com/page` | **no parameter name.** The target is the raw query string, unencoded. `RawQuery` verbatim, do not `ParseQuery` it |
| DeviantArt | `deviantart.com/users/outgoing?<target>` | same bare-query shape as href.li |
| VK | `vk.com/away.php?to=<pct>&cc_key=` | `to`, not `url` |
| YouTube | `youtube.com/redirect?q=<pct>&redir_token=…&event=…&v=…` | `q`, like old Google |
| Slack | `slack-redir.net/link?url=<target>&v=3` | Slack documents nothing; third-party sources and [Rob--W/dont-slack-redir](https://github.com/Rob--W/dont-slack-redir) agree on the shape. Medium confidence |
| Barracuda | `linkprotect.cudasvc.com/url?a=<target>&c=…&d=…` | target in `a`. [Nothing4You/barracuda-url-decoder](https://github.com/Nothing4You/barracuda-url-decoder) does exactly `searchParams.get("a")` and no decode, because `URLSearchParams` already decoded it |
| Cisco Secure Email | `secure-web.cisco.com/<~200-char token>/<percent-encoded target>` | **path, not query.** Take everything after the second path segment and percent-decode once |
| Mimecast | `protect-<region>.mimecast.com/s/<token>?domain=<host>` | host only, and only when the admin enabled it. See §2 |

Cisco, verified against the worked example in
[sthu.org's `ciscoclean`](https://www.sthu.org/code/codesnippets/mutt-cisco-url-rewriting-clean.html):

```
wrapped  https://secure-web.cisco.com/1VqOjcxMgKL3XZ…KKw5/https%3A%2F%2Fwww.example.org%2F
decoded  https://www.example.org/
```

**Not covered in this pass, listed so it is not rediscovered as new:** Symantec
`clicktime.symantec.com`, Trellix/FireEye `protect2.fireeye.com`, Forcepoint,
Sophos. All are believed to be query-parameter wrappers of the same family.
Unverified — do not add rules for them without driving a sample.

---

## For us

### The rule table

One table, data only, living in `rules.go` beside the tracker table
([03 §layout](../03-architecture.md)). Nothing in it may fetch.

```go
// Shape says where the target hides. Four shapes cover all 19 wrappers.
type Shape uint8

const (
	ShapeParam     Shape = iota // "?url=" — the common case
	ShapeBareQuery              // href.li, DeviantArt: RawQuery *is* the target
	ShapePathTail               // Cisco: everything after the token segment
	ShapeCustom                 // urldefense v2/v3, AMP — needs code
)

// Decoder is how the captured string becomes a URL.
type Decoder uint8

const (
	DecodeNone       Decoder = iota // already a URL
	DecodePercent                   // QueryUnescape, once, then the ladder check
	DecodeURLDefenseV1
	DecodeURLDefenseV2
	DecodeURLDefenseV3
	DecodeAMPPath
)

// Wrapper is one entry. Hosts are lowercased; a leading "*." means suffix match.
type Wrapper struct {
	Name    string   // "Microsoft Safe Links" — shown verbatim in the Note
	Hosts   []string // "*.safelinks.protection.outlook.com"
	Path    string   // "" = any; "/l.php", "/url", "/away.php"
	Shape   Shape
	Params  []string // ShapeParam: first one present wins — {"url"}, {"q","url"}
	Decode  Decoder
	Partial bool     // Mimecast: yields a host, not a URL
}
```

`Params` as a *slice* is what lets Google (`q` or `url`) and Steam (`url` or
`u`) be one row rather than two, and it is what a rule table will need again the
next time a vendor renames a parameter without telling anyone.

### Where it plugs in

`Inspection.Unwrapped` already exists ([03 §2](../03-architecture.md#2-domain-types));
each hop becomes a `Layer` with `Method` set to the wrapper name, and the
user-facing sentence becomes a `Note`. The loop must be **bounded** (wrappers
nest — Safe Links around urldefense is routine in organisations running both)
and **cycle-guarded**.

A16 changes the host, so the ordering rule in
[04 §short-links](../04-short-links.md) binds: unwrapping is display-only on
Inspect and explicit opt-in on Clean, never silent inside `clean: true`, and
anything unwrapped is **re-validated** before it is stored or rendered as a
link. Unwrapping an attacker-supplied Safe Links wrapper is how a `file://` or
an internal host gets smuggled past a validation that ran on the wrapper.

### The five that need care

1. **Decode exactly once, then test.** Safe Links, Facebook, Google. Decode
   twice and `%20` in the *target* silently becomes a space. Re-decode only if
   the result is not yet an absolute URL, and cap it.
2. **Read the parameter, never regex the tail.** The `u=…&h=…` bug is the most
   common failure in this whole genre, and reusing A1's ordered pair parser
   makes it structurally impossible.
3. **urldefense v3.** Percent-decode before substitution; base64**url** with
   `==` appended; runs are `**X` with `A`=2; empty replacement string is legal;
   repair the single-slash scheme. A golden-file test per rule is the honest
   minimum here, using the synthetic pairs in §4.
4. **HTML entities.** Links pulled from mail source arrive with `&amp;`.
   Unescape before parsing, or every Safe Links target ends at `sdata`.
5. **Partial results must look partial.** Mimecast yields a domain. Say
   "destination domain: example.com, path not recoverable" and do not render it
   as a link.

### Ship order

| # | Rules | Why |
|---|---|---|
| 1 | Safe Links, urldefense v1/v2/v3 | The whole reason A16 exists. Anyone on Microsoft 365 or Proofpoint — most of corporate email — sees these on every link, every day |
| 2 | `google.com/url`, `l.facebook.com` family, `youtube.com/redirect` | Highest volume outside mail, trivial once §1's decode-once rule is right |
| 3 | Cisco, Barracuda, Mimecast (partial) | Same population as #1, different vendor. Cisco is a path shape, so it proves `ShapePathTail` |
| 4 | Tumblr, Reddit, Steam, VK, href.li, DeviantArt, Slack, LinkedIn interstitial | Long tail. One table row each, near-zero cost |
| 5 | — | `t.co`, `lnkd.in`, `bit.ly`: **never**. They are A6's, and A16's table should carry them only as an explicit "this one needs a fetch" note so the UI can say why |

Row 5 is the point of this report as much as rows 1–4. The value of A16 is that
it is honest about the boundary: everything it claims to unwrap, it unwraps with
certainty and no network, and everything else it names as somebody else's job.
