// Corpberry Link — MV3 service worker.
//
// Two context-menu items on any link:
//   Copy Short Link Address  — one POST to the API, needs a key
//   Copy Clean Link Address  — no network at all, see cleanLocally()
//
// Chrome collapses two or more extension items into a submenu named after the
// extension. That is accepted deliberately: hiding half the functionality
// behind an options-page preference is how features go unused. If the extra
// click proves annoying, keep exactly one item *visible* at a time via
// contextMenus.update({visible}) — that keeps a top-level entry and the setting
// can be flipped from the menu itself.

const DEFAULT_BASE = 'https://link.corpberry.com';
const RULES_ALARM = 'refresh-rules';

// resolveBase gates where the API key may be sent.
//
// A service-worker fetch to an origin NOT in host_permissions is an ordinary
// CORS request, so a hostile server that answers the preflight with
// Access-Control-Allow-Origin: * and Access-Control-Allow-Headers: x-api-key
// simply receives the key. The options page invites the user to edit this
// field, so "whatever they typed" is not an acceptable destination for a
// secret. Anything unrecognised falls back to the default rather than erroring,
// so a typo costs a wrong-server request and never the key.
function resolveBase(configured) {
  if (!configured) return DEFAULT_BASE;
  let u;
  try {
    u = new URL(configured);
  } catch (_) {
    return DEFAULT_BASE;
  }
  if (u.origin === new URL(DEFAULT_BASE).origin) return u.origin;
  // Dev builds only, and only over loopback: a "localhost" that resolves
  // elsewhere cannot be reached over http from here without the user having
  // pointed it there deliberately.
  const devHost = u.hostname === 'localhost' || u.hostname.endsWith('.localhost') ||
    u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol === 'http:' && devHost) return u.origin;
  return DEFAULT_BASE;
}

// --- menu ------------------------------------------------------------------

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'short', title: 'Copy Short Link Address', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'clean', title: 'Copy Clean Link Address', contexts: ['link'] });
  });
  // setTimeout cannot survive service-worker teardown, so a "daily" refresh has
  // to be an alarm. This is why "alarms" is in the manifest.
  chrome.alarms.create(RULES_ALARM, { periodInMinutes: 60 * 24 });
  refreshRules();
});

chrome.alarms.onAlarm.addListener((a) => {
  if (a.name === RULES_ALARM) refreshRules();
});

chrome.contextMenus.onClicked.addListener(async (info) => {
  const url = info.linkUrl;
  if (!url) return;
  await badge('…', '#888888');
  try {
    const text = info.menuItemId === 'clean' ? await cleanLocally(url) : await shorten(url);
    const ok = await copyViaOffscreen(text);
    await badge(ok ? '✓' : '!', ok ? '#2e7d32' : '#c62828');
  } catch (e) {
    await badge('!', '#c62828');
    await notify(String(e.message || e));
  }
  setTimeout(() => badge('', '#000000'), 2000);
});

// --- clipboard -------------------------------------------------------------

// creating: module-scope promise that serialises two callers within one worker
// lifetime. Needed IN ADDITION to the getContexts() check below, not instead of
// it: getContexts catches a document that survived a worker eviction, this
// catches two rapid right-clicks inside one lifetime. Either alone is
// insufficient, and a second createDocument() rejects with
// "Only a single offscreen document may be created."
let creating = null;

async function ensureOffscreen() {
  const existing = await chrome.runtime.getContexts({ contextTypes: ['OFFSCREEN_DOCUMENT'] });
  if (existing.length > 0) return;
  if (creating) { await creating; return; }
  creating = chrome.offscreen.createDocument({
    url: 'offscreen.html',
    reasons: ['CLIPBOARD'],
    justification: 'Write the generated short or cleaned link to the clipboard.',
  });
  try { await creating; } finally { creating = null; }
}

async function copyViaOffscreen(text) {
  await ensureOffscreen();
  // Await the acknowledgement before closing: closing from this side without
  // waiting would race the write.
  const res = await chrome.runtime.sendMessage({ target: 'offscreen', type: 'copy', text });
  try { await chrome.offscreen.closeDocument(); } catch (_) { /* already gone */ }
  return !!(res && res.ok);
}

// --- shorten ---------------------------------------------------------------

async function shorten(url) {
  const { apiKey, baseUrl } = await chrome.storage.sync.get(['apiKey', 'baseUrl']);
  const base = resolveBase(baseUrl);
  if (!apiKey) throw new Error('No API key set. Open the extension options and paste your key.');

  // Fetched from the service worker, not a content script: a service-worker
  // request to a host in host_permissions is exempt from page CORS and is NOT
  // preflighted, which is what makes a custom X-Api-Key header cheap here and
  // expensive anywhere else.
  const res = await fetch(base + '/short', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
    body: JSON.stringify({ url, clean: true }),
  });
  if (res.status === 401) throw new Error('Key rejected.');
  if (res.status === 503) throw new Error('Short links are switched off on the server.');
  if (!res.ok) throw new Error('Server said ' + res.status + '.');
  const data = await res.json();
  if (!data.short) throw new Error('No short link in the response.');
  return data.short;
}

// --- clean -----------------------------------------------------------------

// Cleaning is a pure function of a rule table, so it runs locally and instantly
// rather than costing a round trip. The table is single-sourced in Go and
// fetched from /clean/rules, so the two can never drift.
async function refreshRules() {
  try {
    const { baseUrl } = await chrome.storage.sync.get(['baseUrl']);
    const res = await fetch(resolveBase(baseUrl) + '/clean/rules', {
      headers: { Accept: 'application/json' },
    });
    if (!res.ok) return;
    const rules = await res.json();
    await chrome.storage.local.set({ rules, rulesFetchedAt: Date.now() });
  } catch (_) {
    // Offline or server down: keep whatever is cached. cleanLocally falls back
    // to a built-in list, so the menu item never becomes a dead end.
  }
}

// Fallback list, used before the first successful fetch. Deliberately the
// highest-volume click IDs only — the full table comes from the server.
const FALLBACK = [
  /^utm_/i, /^mtm_/i, /^pk_/i, /^ga_/i,
  'gclid', 'gbraid', 'wbraid', 'gclsrc', 'dclid', 'srsltid',
  'fbclid', 'msclkid', 'ttclid', 'twclid', 'yclid', 'igshid',
  'mc_cid', 'mc_eid', 'mkt_tok', '_hsenc', '_hsmi', 'vero_id', '_openstat',
];

async function cleanLocally(raw) {
  const { rules } = await chrome.storage.local.get(['rules']);
  const names = new Set((rules?.params || []).map((r) => String(r.param || r).toLowerCase()));
  const u = new URL(raw);
  for (const key of [...u.searchParams.keys()]) {
    const k = key.toLowerCase();
    const hit = names.has(k) || FALLBACK.some((f) => (f instanceof RegExp ? f.test(k) : f === k));
    if (hit) u.searchParams.delete(key);
  }
  // Drop a query that is now empty, so the result is not left with a bare "?".
  let out = u.toString();
  if (out.endsWith('?')) out = out.slice(0, -1);
  return out;
}

// --- feedback --------------------------------------------------------------

// Badge text is invisible unless the extension is pinned to the toolbar, and a
// fresh install is unpinned by default. So the badge serves whoever pins it,
// and failures also raise a notification, which does not depend on pinning.
async function badge(text, colour) {
  try {
    await chrome.action.setBadgeBackgroundColor({ color: colour });
    await chrome.action.setBadgeText({ text });
  } catch (_) { /* no action surface: not fatal */ }
}

// notify is best-effort and deliberately not backed by a manifest permission:
// "notifications" would add a second install warning for a failure path, and the
// badge already carries the signal for anyone who pinned the extension. The
// optional chaining means this is simply a no-op when the API is absent.
async function notify(message) {
  try {
    await chrome.notifications?.create({
      type: 'basic', iconUrl: 'icons/128.png', title: 'Corpberry Link', message,
    });
  } catch (_) { /* not granted; the badge already showed "!" */ }
}
