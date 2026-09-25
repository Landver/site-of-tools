# Corpberry Link — browser extension

Adds **Copy Short Link Address** and **Copy Clean Link Address** to the
right-click menu on any link. Vanilla MV3, **no build step** — that is not a
compromise, it is the only shape compatible with the repo's no-Node rule, and
an extension this size needs no bundler.

## Install (developer mode)

This is the intended distribution. See
[`../docs/05-extension.md` §7](../docs/05-extension.md#7-publishing-a-decision-not-a-given)
for why it is not on the Chrome Web Store: the headline feature needs an API key
only the operator has, and the one published extension with that exact model
(Shlink's) has 337 users after four years.

1. `chrome://extensions` → enable **Developer mode**
2. **Load unpacked** → select this directory
3. Open the extension's options, paste your `LINK_API_KEY`, and set the server
   if you are not pointing at `https://link.corpberry.com`

## Files

| | |
|---|---|
| `manifest.json` | MV3. One manifest serves Chrome and Firefox: `background.service_worker` for Chrome, `background.scripts` for Firefox (Chrome ignores `scripts` from 121), plus `browser_specific_settings.gecko` |
| `sw.js` | Menu wiring, the shorten call, local cleaning, badge feedback |
| `offscreen.html` / `offscreen.js` | The clipboard write. Read the comment at the top of the HTML before changing anything here |
| `options.html` / `options.js` | API key + server |
| `icons/` | 16/32/48/128 |

## The two things that will surprise you

**The offscreen document cannot use `navigator.clipboard` either.** A service
worker has no DOM, which is why the offscreen document exists — but that API
also needs a *focused* document, and an offscreen document is never focused, so
it throws `Document is not focused`. The write goes through the deprecated
`document.execCommand('copy')`. Google's own sample does the same.

**`clipboardWrite` is not a free permission.** Unlike `contextMenus`, `storage`,
`offscreen` and `alarms`, it produces a user-facing install warning: *"Modify
data you copy and paste."*

## Permissions, and why each is here

| Permission | Why | Install warning? |
|---|---|---|
| `contextMenus` | The menu items | no |
| `storage` | API key, server, cached rules | no |
| `offscreen` | The only supported clipboard path from a service worker | no |
| `clipboardWrite` | Required for the write itself, in both Chrome and Firefox | **yes** |
| `alarms` | Daily rule refresh — `setTimeout` cannot survive worker teardown | no |
| `host_permissions: link.corpberry.com` | The one host we talk to | yes, names the host |

No `scripting`, no `activeTab`, no `tabs`, no `<all_urls>`.

## Cleaning runs locally

Shortening needs the server; cleaning does not. The rule table is fetched from
`/clean/rules`, cached in `chrome.storage.local` and refreshed daily, so the
common operation costs no round trip and the rules stay single-sourced in Go.
A built-in fallback list covers the highest-volume click IDs before the first
successful fetch, so the menu item is never a dead end.

## Firefox

The same code. `chrome.offscreen` does not exist there and is not needed —
Firefox's MV3 background is an event page with DOM access, so
`navigator.clipboard.writeText` works directly, though it still needs
`clipboardWrite`. `sw.js` feature-detects rather than branching on the browser.

Note Firefox ships **Copy Clean Link** natively, so only the short-link item is
new there.
