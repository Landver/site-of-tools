# The browser-extension shelf

**Checked 2026-09-25.** Every Chrome Web Store row below was read from the
listing itself; permissions come from the **manifest the listing embeds**, not
from a third-party stats site. Firefox and Chrome native behaviour was checked
against release notes and browser source.

Two method notes, because they change how the numbers should be read:

- **Install counts are buckets.** Google rounds above 1,000, so "10,000 users"
  and "500,000 users" are floors, not counts. Under 1,000 the figure is exact.
- `chrome-stats.com` returns 403 to automated fetches and the Chrome Web Store
  refuses to render in an automation browser, so everything here came from the
  listing HTML directly. Where a listing does not show a figure, it says so
  below rather than guessing.

---

## 1. Chrome: copying a cleaned link from the context menu

The shelf is **crowded and tiny**. Eleven listings found, nine of them under
1,000 installs, none above 10,000. Nobody owns this category.

| Extension | Users | Rating | Ver | Last updated | Permissions | Server? |
|---|---|---|---|---|---|---|
| [Linkumori (URLs Cleaner)](https://chromewebstore.google.com/detail/linkumori-urls-cleaner-fo/jchobbjgibcahbheicfocecmhocglkco) | 10,000 | 3.6 (59) | 166.0 | 2025-06-12 | `storage tabs declarativeNetRequest activeTab scripting alarms unlimitedStorage contextMenus webNavigation webRequest downloads` + all hosts | local |
| [URL Cleaner](https://chromewebstore.google.com/detail/url-cleaner/dffbjiomnajbmlhjelpipfldgkijdemn) | 9,000 | 3.5 (10) | 0.1.0 | 2026-04-21 | `activeTab clipboardWrite storage declarativeNetRequestWithHostAccess` + `http/https://*/*` | local |
| [Copy Clean Link](https://chromewebstore.google.com/detail/copy-clean-link/oegijnfjkadehneapgaejnnappgdpgng) (skyrocker2013) | 1,000 | **2.7** (7) | 1.0.4 | 2026-02-16 | `storage contextMenus clipboardWrite activeTab scripting alarms` | local |
| [Sanitize It](https://chromewebstore.google.com/detail/sanitize-it/cdihhogfljcidhcpjdhhelbmbhbeafgd) | 563 | 4.8 (4) | 2.4.1 | 2026-07-30 | `activeTab scripting clipboardWrite tabs storage contextMenus` | local |
| [Clean Link — Link Cleaner & Clear URL](https://chromewebstore.google.com/detail/clean-link-%E2%80%94-link-cleaner/fcbdnogkcfgejppcfcakldilfnfdlifp) | 451 | not shown | 1.0.3 | 2026-07-29 | `tabs activeTab storage clipboardWrite alarms notifications` + **`https://qwhub.com/*`** | **calls a server** |
| [copy-clean-url](https://chromewebstore.google.com/detail/copy-clean-url/hgabmjhapckfljffgamminipchfjddka) | 372 | not shown | 0.0.2 | 2023-05-03 | `contextMenus clipboardWrite activeTab scripting` | local, abandoned |
| [Copy Clean Link – Remove URL Tracking](https://chromewebstore.google.com/detail/copy-clean-link-remove-ur/jimbfjhnmbojbhihalhngfkcbmgnjafa) | 158 | none (0) | 1.2 | 2026-01-29 | `contextMenus clipboardWrite scripting tabs storage` + **`<all_urls>`** | local |
| [Copy Clean Link](https://chromewebstore.google.com/detail/copy-clean-link/jfbfabjndmdphkgfomacbooifhngkhmi) (mahadi) | 18 | 5.0 (1) | 1.0.0 | 2026-04-13 | `activeTab clipboardWrite contextMenus offscreen scripting storage`, min Chrome 109 | local |
| [CleanLink Copier](https://chromewebstore.google.com/detail/cleanlink-copier-%E2%80%93-remove/fghkejfklclmekcfoopmbjehgmoemopk) | 18 | none (0) | 1.0.0 | 2025-12-16 | `contextMenus scripting activeTab` | local |
| [LinkCleaner Pro](https://chromewebstore.google.com/detail/linkcleaner-pro/mmahmbfpiejgbiecoacllpjjnjgbdccp) | 8 | not shown | 1.0 | 2026-01-04 | `activeTab clipboardWrite` | local |
| [Clean URL Copy](https://chromewebstore.google.com/detail/clean-url-copy/jincagaldnkgbilbocokpfpekoeekdih) | not shown | none (0) | 1.0.0 | 2025-12-18 | `activeTab scripting` | local |

### What the shelf actually tells us

- **Four are genuinely maintained** in 2026 (Linkumori is 2025 but heavily
  versioned; URL Cleaner, Sanitize It, Clean Link, Copy Clean Link – RUT all
  shipped this year). The rest are one-version drops.
- **Everyone claims local.** Only one is not: *Clean Link — Link Cleaner & Clear
  URL* declares `https://qwhub.com/*` in `host_permissions`, so it phones home
  while the shelf around it advertises "no backend". Nobody's listing mentions
  the difference, and a user comparing two listings cannot see it. **The
  manifest is the only honest signal, and the store does not surface it.**
- **Permission bloat is the norm at the top and the exception at the bottom.**
  Linkumori asks for eleven permissions including `webRequest`, `downloads` and
  all hosts; LinkCleaner Pro asks for two. Both do roughly the advertised job.
- **Quality is uncorrelated with installs.** The 1,000-user *Copy Clean Link*
  scores **2.7** and works by stripping everything after `?` — no rule table at
  all. The 563-user *Sanitize It* has Smart Mode that preserves YouTube video
  IDs and search queries, is open source, and scores 4.8 on four ratings. The
  better product has a fifth of the installs.
- **One of them is already our exact architecture.** *Copy Clean Link* (mahadi)
  declares `offscreen` + `clipboardWrite` with `minimum_chrome_version: 109` —
  i.e. someone else independently hit
  [05 §1](../05-extension.md#1-the-clipboard-problem-in-full)'s offscreen
  clipboard problem and solved it the same way. 18 users.

## 2. ClearURLs as a shipped product

Distinct from its rule catalog, which
[tracking-parameter-reference.md](tracking-parameter-reference.md) measured separately.

| | |
|---|---|
| Firefox (AMO) | **515,240 users**, 4.3 from 1,124 reviews, v1.27.3, updated **2025-02-05** ([listing](https://addons.mozilla.org/en-US/firefox/addon/clearurls/)) |
| Chrome | **No live Web Store listing.** See below |
| Permissions (AMO) | download files + read/modify download history · access browser tabs · access browser activity during navigation · access data for all websites |
| Context-menu copy | **Yes** — "Adds an entry to the context menu so that links can be copied quickly and cleanly" ([docs](https://docs.clearurls.xyz/latest/)) |

**In-browser it does far more than copy.** Per its own docs: automatic cleaning
of URLs during navigation from the rule catalog, a batch multi-URL cleaning
tool, redirection straight to the destination without the tracking middleman,
blocking hyperlink auditing (ping tracking), blocking ETag tracking, blocking
history-API tracking injection, and optional ad-domain blocking. The
context-menu copy is one line item in a privacy suite, not the product.

**The Chrome story is the interesting part.** Fetching
`chromewebstore.google.com/detail/clearurls/lckanjgmijmafbedllaakclkaicjfmnk`
today redirects to `/detail/empty-title/<id>` and returns generic Chrome Web
Store metadata with no listing. The project's own docs explain why:

> Chrome, Edge and Brave users: Google is phasing out the Manifest V2 technology
> that ClearURLs is built on, so Chrome-based browsers may disable the add-on
> until a Manifest V3 version is available; Edge is expected to follow. Firefox
> is not affected. — [docs.clearurls.xyz](https://docs.clearurls.xyz/latest/)

The [GitHub README](https://github.com/ClearURLs/Addon) offers install buttons
for Firefox and Edge only. Chrome was also removed once before, in March 2021,
over a listing-description policy call
([BleepingComputer](https://www.bleepingcomputer.com/news/security/google-removes-privacy-focused-clearurls-chrome-extension/)).

So: **the 515k-user incumbent has left the field we are considering entering.**
Half a million people use it on Firefox, where the same job now ships natively,
and ~zero use it on Chrome, where it doesn't.

## 3. Context-menu URL shorteners, and how they handle the key

| Extension | Users | Rating | Ver | Last updated | Permissions | Auth model |
|---|---|---|---|---|---|---|
| [Bitly \| Short links and QR Codes](https://chromewebstore.google.com/detail/bitly-short-links-and-qr/iabeihobmhlgpkcgjiloemdbofjbdcic) | **500,000** | 3.7 (1.6K) | 4.5.3 | 2026-09-11 | `activeTab clipboardWrite storage contextMenus` + `api-ssl.bitly.com`, min Chrome 88 | **Account sign-in required** |
| [Url Shortener](https://chromewebstore.google.com/detail/url-shortener/oodfdmglhbbkkcngodjjagblikmoegpa) (t.ly) | **300,000** | 3.7 (175) | 2.1.100 | 2026-09-13 | `activeTab contextMenus storage`, **no host permissions** | Anonymous works; token unlocks features |
| [URL Shortener – TinyURL Extension](https://chromewebstore.google.com/detail/url-shortener-tinyurl-ext/mnnjjchefohcoocleiepmdpfhdpgoflk) | 6,000 | 4.1 (13) | 1.0.0 | 2026-06-27 | `activeTab scripting contextMenus clipboardWrite` | None, and it is breaking |
| [Shlink](https://chromewebstore.google.com/detail/shlink/mgdacpmionfhhogkokjbdeehfnnliajj) (unofficial) | 337 | none (0) | 0.6.1 | 2025-04-20 | `activeTab offscreen notifications clipboardWrite storage`, min Chrome 121 | **Bring your own server + API key** |
| [Dub.co Link Shortener](https://chromewebstore.google.com/detail/dubco-link-shortener-repl/ninmnkcainfimpdekpiblgokdbdfipin) | 43 | none (0) | 0.0.1 | 2025-05-16 | `contextMenus storage activeTab scripting` | Dub API, onboarding never explained |
| [OkShort URL Shortener](https://chromewebstore.google.com/detail/okshort-url-shortener/ngdcaapalppcoafjjnkjmpljipmjefki) | 17 | not shown | 1.40.3 | **2021-09-09** | `contextMenus activeTab scripting` + `<all_urls>` | None; abandoned |
| Kutt | — | — | — | — | — | **Listing gone** (same empty-title redirect as ClearURLs) |

### Four distinct onboarding answers

1. **Gate everything behind an account (Bitly).** "Log in to your Bitly account"
   is step one after install
   ([Bitly](https://bitly.com/blog/bitly-chrome-extension/)). 500k installs and
   **3.7 stars** — the lowest-rated of the big two, on 1,600 ratings. An account
   wall is survivable at scale but it costs you a star.
2. **Anonymous by default, key for extras (t.ly).** Basic shortening is free and
   keyless; a T.LY API token pasted into options unlocks branded domains,
   custom endings, expiry, stats. Other back-ends (Bitly, Rebrandly) need their
   own keys. 300k installs, also 3.7. Note its manifest declares **no host
   permissions at all** — the API is reached by plain CORS from the service
   worker, which is a cleaner install-warning story than our current draft.
3. **No key, unauthenticated endpoint (TinyURL).** Works with zero setup, and is
   rotting in public. From the listing's own dev update: *"TinyURL has
   deprecated the old unofficial and unauthenticated API endpoint, which this
   extension uses, and introduced an interstitial preview page on all TinyURL
   links created via the deprecated endpoint."* Free and keyless has an expiry
   date.
4. **Bring your own server (Shlink).** The closest analogue to our situation,
   and the one worth reading twice. The listing opens with: *"You will need to
   run your own instance of Shlink for this extension to function!"* Setup is
   "enter your API key and the location of your Shlink instance" in preferences.
   It is published, MV3, and has **337 users and zero ratings** after four
   years.

Shlink also validates two of [05](../05-extension.md)'s design calls outright:
it declares `offscreen` + `clipboardWrite` (the 05 §1 clipboard route) and
declares **both `service_worker` and `scripts`** in `background` (the 05 §6
one-manifest-two-browsers trick).

## 4. Firefox's native Copy Clean Link

Shipped, on by default, and with a bigger rule table than most of section 1.

| | |
|---|---|
| Landed | **Firefox 120**, 2023-11-21, as "Copy Link Without Site Tracking" on the link context menu ([release notes](https://www.firefox.com/en-US/firefox/120.0/releasenotes/)) |
| Renamed | **Firefox 135**, 2025-02-04, to **"Copy Clean Link"**, and extended to plain-text links ([release notes](https://www.firefox.com/en-US/firefox/135.0/releasenotes/) · [bug 1924493](https://bugzilla.mozilla.org/show_bug.cgi?id=1924493)) |
| Why renamed | "Copy Trimmed Link" tested poorly; the new name limits expectations to cleaning, not de-tracking |
| Default | **On, desktop only.** `StaticPrefList.yaml` defaults `privacy.query_stripping.strip_on_share.enabled` to `false`; `browser/app/profile/firefox.js` overrides it to `true` under the comment *"Enable Strip on Share by default on desktop"* |
| Menu id | `#context-stripOnShareLink` |

**What it strips.** Two bundled JSON lists, combined at runtime by
`URLQueryStrippingListService.sys.mjs`, deliberately split by licence:

| List | Entries | Params | Global params |
|---|---|---|---|
| `StripOnShareLists/MPL2/StripOnShare.json` | 15 | 247 | 182 |
| `StripOnShareLists/LGPL/StripOnShareLGPL.json` | 34 | 244 | 17 |
| **combined** | **49** | **491** | **199** |

The MPL-2 list is global-heavy (the whole `utm_*` family, `_gl`, `li_fat_id`)
with per-site entries for twitter, instagram, amazon, spotify, facebook,
linkedin, ebay and others. The LGPL list is the opposite shape — mostly
per-site, for youtube, etsy, tiktok, bbc, cnn, imdb, bloomberg, forbes — and its
segregation into a separate file under a separate licence is a **precedent worth
noting for us**: Mozilla treats a borrowed cleaning catalogue as a licensing
fact to be isolated, not absorbed.

**The catch that makes it less useful than it sounds.** Firefox shows *both*
"Copy Link" and "Copy Clean Link", and greys the latter out when the link has
nothing to strip. From a user who wrote CSS to fix it:

> One of my major complaints was that when right-clicking a link, I was
> presented with two buttons: one for 'Copy Link', and one for 'Copy Clean Link'
> — with the latter 99.99% of the time being greyed out due to the link already
> being 'clean'.
> — [Joshua Rogers, 2026-03-17](https://joshua.hu/firefox-always-copy-clean-link-url-userchrome-css)

There is no "always copy clean" preference; making `Copy Link` clean silently
requires `userChrome.css`. So the native feature is **present, default-on, and
inert on the large majority of right-clicks**.

## 5. Chrome's own context menu

**No native equivalent, and nothing staged.** Checked firsthand against
Chromium's string resources on `main`
([`chrome/app/generated_resources.grd`](https://chromium.googlesource.com/chromium/src/+/main/chrome/app/generated_resources.grd),
fetched 2026-09-25, 1.44 MB). The complete set of link-copy commands is three:

| Message id | String |
|---|---|
| `IDS_CONTENT_CONTEXT_COPYLINKLOCATION` | Copy link address |
| `IDS_CONTENT_CONTEXT_COPYLINKTEXT` | Copy link text |
| `IDS_CONTENT_CONTEXT_COPYLINKTOTEXT` | Copy link to highlight |

Zero matches in the whole file for `clean link`, `without site tracking`,
`strip on share` / `stripOnShare`, `tracking parameter`, `utm_`, `fbclid` or
`sanitize url`. Chrome ships "Copy link to highlight" — Firefox ships "Copy
**Clean** Link to Highlight" — and that gap is the shelf in section 1.

This confirms [05](../05-extension.md)'s premise: on Chrome, ours would sit
alongside `Copy link address`, and there is nothing native to be redundant with.

---

## For us

**Does a Web Store listing make sense when the headline feature needs a key only
the owner has?** The shelf says it is *allowed* and *pointless*. Shlink is the
control experiment: a published, MV3, actively-built extension that announces
"you will need to run your own instance" in its first sentence, four years old,
**337 users and zero ratings**. Kutt tried the same and its listing is gone.
Meanwhile Bitly's account wall costs it a star across 1,600 ratings, and t.ly —
the one that works keylessly on first click — gets 300k installs on the same
rating. Nothing here contradicts
[05 §7](../05-extension.md#7-publishing--a-decision-not-a-given)'s **~70% lean
against publishing for v1**; if anything the Shlink number raises it. The store
listing buys a few hundred installs of a button that returns an error, plus the
$5, the privacy-practices tab, the trader declaration and permanent MV3
maintenance. Load-unpacked stays the honest distribution.

Two findings that *would* change the calculus if the key model ever changes.
t.ly reaches its API with **no `host_permissions` at all**, on plain CORS from
the service worker, which is a materially quieter install prompt than our
drafted manifest — worth testing against `link.corpberry.com` before assuming we
need the host permission. And TinyURL is the cautionary tale in the other
direction: the keyless path it depends on got deprecated and interstitialled out
from under it. Our closed write path is not only a privacy decision, it is the
reason we will not wake up to someone else's interstitial.

**What would differentiate ours.** Not cleaning, and not shortening. Three
things the shelf does not have:

1. **Both actions from one menu, one rule table, one round-trip budget.** Every
   extension found does exactly one of the two. Ours is the only one where
   Clean is free and instant and Short costs a round trip, and where both read
   the same Go-sourced rules.
2. **Rules single-sourced from a server we control and published as JSON.**
   Section 1's extensions each carry a private, unversioned, unauditable list;
   the one that fetches rules from a server (`qwhub.com`) does not disclose it.
   `GET /clean/rules` with `Accept: application/json` is a differentiator
   precisely because it is checkable.
3. **Honesty about what cleaning did.** calcbe's lesson —
   [the copy button quietly repaired `%zz`](calcbe-query-string-parser.md#one-inconsistency-worth-recording)
   — is unsolved on this shelf too. The 1,000-user *Copy Clean Link* deletes
   everything after `?` and says nothing. Reporting *which* parameters were
   removed is a two-line notification nobody ships.

**Is the Clean half worth shipping at all?** Yes, and for a narrower reason than
"Chrome lacks it". Firefox's native item is default-on but **greyed out on
almost every link**, with no always-clean preference, which is why people write
`userChrome.css` to force it. Chrome has nothing at all, and the eleven
substitutes are a mix of two-permission toys, one eleven-permission suite, one
that strips everything after `?`, and one that phones home without saying so.
The bar is low. It is also cheap for us: Clean is a pure function of a rule
table we already build, it needs no server round trip, no key, and no host
permission beyond the daily rules fetch. Ship it.

Where it does *not* pay is as a reason to publish. Clean is redundant on
Firefox, adequately covered on Chrome for anyone willing to install a stranger's
extension, and — per
[05 §2](../05-extension.md#2-one-menu-item-or-two) — adding it as a second item
demotes Short into a submenu. Build Clean because it costs almost nothing and
we'll use it. Don't build it to have something to list.
