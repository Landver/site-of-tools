# The browser extension

Adds **Copy Short Link Address** next to Chrome's own *Copy Link Address* on the
right-click menu of any link. `chrome.contextMenus` with `contexts: ["link"]` is
the API this exists for and hands the handler `info.linkUrl` directly. There is
no way to remove, reorder or override Chrome's built-ins, so ours can only sit
alongside — which is what was wanted.

Lives at `tools/linktools/extension/`, co-located with the tool it talks to. No
`.go` files, so the Go toolchain ignores it. Vanilla MV3, **no build step** —
not a compromise but the only shape compatible with rule #3's no-Node rule.

All API facts below verified against current docs on 2026-09-25; sources inline.

---

## 1. The clipboard problem, in full

MV3 background service workers have no DOM, so `navigator.clipboard` does not
exist there. The supported answer is the **offscreen document API**
(`chrome.offscreen`, Chrome 109+) with `reasons: ["CLIPBOARD"]`.

**The catch the first draft missed: the offscreen document cannot use
`navigator.clipboard` either.** That API requires a focused document, and an
offscreen document is never focused — it throws `DOMException: Document is not
focused`. The write has to go through the deprecated
`document.execCommand('copy')` against a selected `<textarea>`, which is exactly
what Google's own
[`cookbook.offscreen-clipboard-write`](https://github.com/GoogleChrome/chrome-extensions-samples/tree/main/functional-samples/cookbook.offscreen-clipboard-write)
sample does: `offscreen.html` is one `<textarea>`; `offscreen.js` is
`el.value = data; el.select(); document.execCommand('copy')`.
([MDN](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/Interact_with_the_clipboard)
states it flatly.)

```js
// sw.js
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({ id: "short", title: "Copy Short Link Address", contexts: ["link"] });
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  const text = await shorten(info.linkUrl);   // one POST; an in-flight fetch keeps the worker alive
  await copyViaOffscreen(text);
});
```

### Three sharp edges in `copyViaOffscreen`

Google's sample is a minimal demo. Whoever writes this will start from it and
should know:

- **`createDocument` must be guarded, and one guard is not enough.** An
  extension may have exactly one offscreen document; a second call rejects with
  *"Only a single offscreen document may be created."* Two rapid right-clicks
  hit this. The fix needs **both** halves:
  `chrome.runtime.getContexts({contextTypes: ['OFFSCREEN_DOCUMENT']})`
  (Chrome 116+) to catch a document that survived a worker eviction, **and** a
  module-scope `creating` promise to serialise two callers within one worker
  lifetime. (`chrome.offscreen.hasDocument()` is simpler but is Chrome 150+,
  which would raise the floor a long way above 109.)
- **`sendMessage` is fire-and-forget in the sample.** Have the offscreen
  document `sendResponse`, and await it — that acknowledgement is the signal
  §3's feedback needs to show ✓ versus !.
- **Close only after the acknowledgement.** The sample is safe because it calls
  `window.close()` from inside the offscreen document's `finally`, after a
  *synchronous* `execCommand`. It stops being safe the moment anyone closes from
  the service-worker side without awaiting.

Two things that are already right: registering `onMessage` at top-level script
execution guarantees the offscreen document is listening by the time
`createDocument()` resolves, and `chrome.runtime.sendMessage` from the service
worker is not delivered to the worker's own listener, so a `target` filter is
hygiene rather than a correctness requirement.

## 2. One menu item, or two

Chrome shows a single extension item at the **top level**. Add a second and
Chrome collapses **both** into a submenu named after the extension — so "Copy
Short Link Address" stops being one click. Firefox behaves the same and says so
more explicitly.

| | Result |
|---|---|
| **One item, short only** | Top-level, one click. No clean action |
| Two items | Both behind a submenu, two clicks each |
| One item, behaviour set in options | Top-level, one click; the user must find the setting |
| **One item *visible* at a time**, toggled via `contextMenus.update({visible})` | Top-level, one click, and the setting can be flipped from the menu itself rather than from an options page |

There is no documented flag, no `update()` override and no other way to pin one
item to the top level while a second is visible. (`ACTION_MENU_TOP_LEVEL_LIMIT`
in the same API reference is easy to misread — it applies only to the extension
action's *own* context menu, i.e. right-clicking the toolbar icon.)

**Decision: ship one item ("Copy Short Link Address") in Phase 1**, which is
also the only one that works before Clean exists. Add the second when Clean
ships, and if the submenu proves annoying, switch to the `visible`-toggle row —
which is strictly better than the options-page variant and costs two lines.
Deciding it after using it beats arguing about it now.

## 3. Cleaning without a round trip, and the latency that can't be avoided

Shortening must hit the server. Cleaning does not: it is a pure function of a
rule table. So the extension fetches `GET /clean/rules` with
`Accept: application/json`, caches it in `chrome.storage.local`, and cleans
**locally and instantly**. The rules stay single-sourced in Go, so the two can
never drift.

Refreshing "daily" needs `chrome.alarms` — `setTimeout` cannot survive service
worker teardown. Either add `"alarms"` to permissions (no user-facing warning)
or refresh opportunistically on the first click after the `ETag` goes stale.
Pick one; as first drafted the doc described behaviour the manifest could not
deliver.

**The short path has an unavoidable round trip** between the click and the
clipboard having content. Paste too fast and you paste stale content.

- **Feedback: `chrome.action.setBadgeText`** — `…` on click, `✓` on success, `!`
  on failure. **But badge text is invisible unless the extension is pinned to
  the toolbar, and a fresh install is unpinned by default**, so badge-only
  feedback silently does nothing for most users. Pair it with
  `chrome.notifications` on failure, or accept that the badge serves the owner
  (who will pin it) and not a general installer. Note also that the
  badge-clearing `setTimeout` can itself be lost to worker teardown.
- **Deterministic local codes**, so the short URL could be computed before the
  server confirms, are rejected: they force hash-of-target codes, which
  [04 §3](04-short-links.md#3-codes) rules out as a privacy oracle.

## 4. Manifest

```json
{
  "manifest_version": 3,
  "name": "Corpberry Link",
  "version": "1.0.0",
  "minimum_chrome_version": "116",
  "description": "Copy a short or tracker-free version of any link from the right-click menu.",
  "permissions": ["contextMenus", "storage", "offscreen", "clipboardWrite", "alarms"],
  "host_permissions": ["https://link.corpberry.com/*"],
  "background": { "service_worker": "sw.js", "type": "module" },
  "action": {},
  "options_ui": { "page": "options.html", "open_in_tab": true },
  "icons": { "16": "…", "32": "…", "48": "…", "128": "…" }
}
```

Corrections against the first draft:

- **`clipboardWrite` is required and is not free.** Google's own offscreen
  sample declares it, and unlike the others it produces a user-facing install
  warning: **"Modify data you copy and paste."** So the honest summary is three
  silent permissions plus one warned permission plus a single host permission —
  not "nothing alarming".
- **`alarms`** per §3, if the daily refresh is kept.
- **`action: {}`** because §3's badge feedback needs it. The key is documented
  as optional, but Google's own sample declares it and it is the safe path.
- **`options_ui`** supersedes the legacy `options_page`, which still works.
- **`minimum_chrome_version: "116"`** — `chrome.offscreen` floors at 109, but
  `runtime.getContexts()` (§1's guard) needs 116. Free insurance.
- No `scripting`, no `activeTab`, no `tabs`, no `<all_urls>`. Chrome's docs
  single out broad host patterns as slowing review.

**CORS — the main claim holds, the fallback did not.** A fetch from an MV3
*service worker* to a host in `host_permissions` is exempt from page CORS;
*content scripts* in MV3 are not, which is the MV2→MV3 tightening. That
exemption means **no preflight at all**, which is exactly what makes a custom
`X-Api-Key` header cheap here and expensive in a content script. If it ever
misbehaved, the Go-side fix would *not* be one header: a `POST` carrying
`X-Api-Key` and a JSON content type is preflighted, needing an `OPTIONS` route
plus `Allow-Origin`, `-Methods` and `-Headers`. Expect `Origin:
chrome-extension://<id>` on the request; don't write an allowlist that rejects
it.
([Chrome network-requests docs](https://developer.chrome.com/docs/extensions/develop/concepts/network-requests))

## 5. Options page

Two fields: **API key** and **base URL** (default `https://link.corpberry.com`,
overridable so a dev build can point at `link.localhost:8080`).

`chrome.storage.sync` quotas are ample — 102,400 bytes total, 8,192 per item,
512 items, 1,800 writes/hour. Three things worth stating rather than discovering:

1. **It is not encrypted.** The key sits in plaintext on disk and any code in
   the extension's context can read it. (`storage.session` is the docs' advice
   for sensitive data, but it is in-memory and cleared on browser close, so it
   cannot hold a persisted key.)
2. **`sync` propagates the key to every Chrome profile signed into that Google
   account**, including machines the user may not think of as trusted.
   `storage.local` keeps it on one machine at the cost of re-pasting. For a
   single-operator tool `sync` is probably still right, but it is a choice.
3. An API key counts as **"Authentication information"** on the Chrome Web Store
   privacy-practices tab and must be declared there.

## 6. Firefox

Nearly the same code, four differences:

- **No `background.service_worker`** (Firefox bug 1573659) — Firefox uses
  `background.scripts`. Since Firefox 121 a background page starts correctly
  even when `service_worker` is also present, so **one manifest can serve both**
  if it declares `scripts` alongside `service_worker` (Chrome ignores `scripts`
  from Chrome 121) plus `browser_specific_settings.gecko.id`.
- **No `chrome.offscreen`**, and none needed: the event page has DOM access, so
  `navigator.clipboard.writeText` works directly — **but it still needs
  `clipboardWrite`**, which also removes the transient-activation requirement.
  Same permission as Chrome, so adding it once fixes both branches.
  Feature-detect `chrome.offscreen`; don't branch on the browser.
- **`browser.menus` needs the `"menus"` permission**; `browser.contextMenus` is
  the alias needing `"contextMenus"`. Chrome supports neither `browser.menus`
  nor `menus`. For one shared codebase, stay on `contextMenus`.
- **AMO has no fee, but "faster review" is the wrong framing.** Listed
  submissions are validated, signed and published quickly, with human review
  *after* publication unless something trips a flag; when a manual review is
  triggered the queue runs days to weeks.

**Firefox already ships "Copy Clean Link" natively**
([Bugzilla 1924493](https://bugzilla.mozilla.org/show_bug.cgi?id=1924493)), so
the second menu item is redundant there on arrival. The short-link item is not.

## 7. Publishing — a decision, not a given

The first draft treated a Chrome Web Store listing as the obvious endpoint. It
isn't, for a reason internal to the design:

**The headline feature cannot be used by anyone who installs it from the store.**
Shortening requires `LINK_API_KEY`, which only the owner has, and
[04 §5](04-short-links.md#5-authentication-and-why-the-write-path-is-closed)
rules out public creation permanently. Meanwhile the other item is native in
Firefox and has [several existing Chrome implementations](https://chromewebstore.google.com/detail/copy-clean-link-remove-ur/jimbfjhnmbojbhihalhngfkcbmgnjafa),
and context-menu shorteners have existed for years
([00 §2](00-landscape.md#2-the-extension-shelf--where-the-deliverable-actually-sits)).

So a listing costs $5, a privacy policy, screenshots, a trader declaration,
privacy-practices disclosures, a single-purpose statement, per-permission
justifications and ongoing MV3 maintenance — in exchange for a listing whose
main feature is inert for every installer.

> **Lean: don't publish for v1, ~70%.** "Load unpacked" in developer mode is the
> honest distribution for a single-operator tool, and it needs none of the
> above. Publish later *if* the key model ever changes.

Note that self-hosting a `.crx` is not a general alternative either: Chrome has
blocked external installs from a local CRX path since Chrome 33 on Windows and
Chrome 44 on macOS. **Only Linux still permits it**, via an external-extensions
preferences JSON. On this Mac, the real options are the Web Store or unpacked.
([Chrome distribution docs](https://developer.chrome.com/docs/extensions/how-to/distribute/install-extensions))

### If it is published anyway — the current checklist

- **$5** one-time developer registration; **2-Step Verification mandatory**.
- **Review**: the docs now say a few days for most extensions, up to a few
  weeks, and past three weeks you contact developer support. The old "under an
  hour" and "90% under 3 days" figures are gone. A first submission from a new
  developer account gets closer scrutiny by policy. Don't promise a date.
- **Trader / non-trader declaration** — mandatory under the EU DSA since
  Feb 2024. Traders' contact details are verified and publicly displayed on the
  listing. A solo operator publishing a free tool normally declares non-trader,
  but it is a required step.
- **Privacy-practices tab + Limited Use certification** — separate from the
  privacy policy URL, and you cannot publish or update without completing it.
- **Policy updates effective 1 Aug 2026**: Limited Use now requires collected
  data be strictly necessary to the disclosed single purpose, and all collection
  must be prominently disclosed regardless of how closely related it is.
  "Web browsing activity" explicitly includes "the domains or URLs" a user
  requests, collectable only for a user-facing feature described prominently
  **in the listing and in the UI** — not only in the privacy policy. Shortening
  is that feature; it has to be said out loud.
- **Privacy policy URL** — serve it from the Go app at
  `link.corpberry.com/extension/privacy` so it versions with the code.
- **Assets**: manifest icons 16/32/48/128 are *not* the listing assets. The
  listing needs a 128×128 store icon (96×96 artwork + 16px transparent padding),
  1–5 screenshots at 1280×800 or 640×400 (full bleed, square corners, no
  padding), and a 440×280 small promo tile (listings without one rank behind
  those with one). A 1400×560 marquee is optional but required for marquee
  featuring.

Sources: [review process](https://developer.chrome.com/docs/webstore/review-process) ·
[trader disclosure](https://developer.chrome.com/docs/webstore/program-policies/trader-disclosure) ·
[user-data FAQ](https://developer.chrome.com/docs/webstore/program-policies/user-data-faq) ·
[2026 policy updates](https://developer.chrome.com/blog/cws-policy-updates-2026) ·
[listing images](https://developer.chrome.com/docs/webstore/images)
