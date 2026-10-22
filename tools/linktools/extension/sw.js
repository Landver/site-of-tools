// Corpberry Link MV3 service worker.
// Chrome nests the two menu items in a submenu: accepted, as an item hidden behind an option goes unused.

const DEFAULT_BASE = 'https://link.corpberry.com';
const RULES_ALARM = 'refresh-rules';

// Gates where the API key may go: a foreign origin answering CORS preflight permissively would receive it.
// Anything unrecognised falls back to the default, so a typo costs a wrong request, never the key.
function resolveBase(configured) {
  if (!configured) return DEFAULT_BASE;
  let u;
  try {
    u = new URL(configured);
  } catch (_) {
    return DEFAULT_BASE;
  }
  if (u.origin === new URL(DEFAULT_BASE).origin) return u.origin;
  // Dev builds only, and only over loopback.
  const devHost = u.hostname === 'localhost' || u.hostname.endsWith('.localhost') ||
    u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol === 'http:' && devHost) return u.origin;
  return DEFAULT_BASE;
}

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'short', title: 'Copy Short Link Address', contexts: ['link'] });
    chrome.contextMenus.create({ id: 'clean', title: 'Copy Clean Link Address', contexts: ['link'] });
  });
  // setTimeout dies with the worker, so the daily refresh has to be an alarm.
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

// Serialises rapid clicks in one worker lifetime; getContexts() catches a document left by an evicted one.
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
  // Firefox has no chrome.offscreen: its MV3 event page has a DOM, so the clipboard API works directly.
  if (!chrome.offscreen) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch (e) {
      return false;
    }
  }

  await ensureOffscreen();
  const res = await chrome.runtime.sendMessage({ target: 'offscreen', type: 'copy', text });
  // Not closed: an overlapping second click would lose it. It is cheap and dies with the worker.
  return !!(res && res.ok);
}

async function shorten(url) {
  const { apiKey, baseUrl } = await chrome.storage.sync.get(['apiKey', 'baseUrl']);
  const base = resolveBase(baseUrl);
  if (!apiKey) throw new Error('No API key set. Open the extension options and paste your key.');

  // From the worker, a fetch to a host_permissions origin skips the CORS preflight X-Api-Key would cost.
  const res = await fetch(base + '/short', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-Api-Key': apiKey },
    body: JSON.stringify({ url, clean: true }),
    // fetch replays headers on redirect, leaking X-Api-Key off-origin; this endpoint never redirects.
    redirect: 'error',
  });
  if (res.status === 401) throw new Error('Key rejected.');
  if (res.status === 503) throw new Error('Short links are switched off on the server.');
  if (!res.ok) throw new Error('Server said ' + res.status + '.');
  const data = await res.json();
  if (!data.short) throw new Error('No short link in the response.');
  return data.short;
}

// The rule table is single-sourced in Go and fetched from /clean/rules, so local cleaning cannot drift.
async function refreshRules() {
  try {
    const { baseUrl } = await chrome.storage.sync.get(['baseUrl']);
    const res = await fetch(resolveBase(baseUrl) + '/clean/rules', {
      headers: { Accept: 'application/json' },
      redirect: 'error',
    });
    if (!res.ok) return;
    const rules = await res.json();
    await chrome.storage.local.set({ rules, rulesFetchedAt: Date.now() });
  } catch (_) {
    // Offline: keep the cache; cleanLocally falls back to FALLBACK.
  }
}

// Used before the first successful fetch: the highest-volume click IDs only.
const FALLBACK = [
  /^utm_/i, /^mtm_/i, /^pk_/i, /^ga_/i,
  'gclid', 'gbraid', 'wbraid', 'gclsrc', 'dclid', 'srsltid',
  'fbclid', 'msclkid', 'ttclid', 'twclid', 'yclid', 'igshid', 'igsh',
  'mc_cid', 'mc_eid', 'mkt_tok', '_hsenc', '_hsmi', 'vero_id', '_openstat',
];

// No hosts means global; otherwise match on a label boundary, never a bare endsWith.
function hostMatches(host, hosts) {
  if (!hosts || !hosts.length) return true;
  return hosts.some((h) => {
    h = String(h).toLowerCase().replace(/\.$/, '');
    return host === h || host.endsWith('.' + h);
  });
}

function ruleHits(key, host, rules) {
  // never_strip wins: these look like tracking but break things (redirect_uri, state, signature).
  for (const d of rules.never_strip || []) {
    const p = String(d.param || '').toLowerCase();
    if (!hostMatches(host, d.hosts)) continue;
    if (d.prefix ? key.startsWith(p) : key === p) return null;
  }
  for (const r of rules.tracking || []) {
    const p = String(r.param || '').toLowerCase();
    // Affiliate tags stay, as on the server: stripping one takes money from the reviewer you followed.
    if (r.class === 'affiliate') continue;
    if (!hostMatches(host, r.hosts)) continue;
    if (r.prefix ? key.startsWith(p) : key === p) return r;
  }
  return null;
}

// Edits the original query bytes: searchParams.toString() re-encodes, and like the Go cleaner
// the output must equal the input byte for byte when nothing is stripped.
async function cleanLocally(raw) {
  const { rules } = await chrome.storage.local.get(['rules']);
  const u = new URL(raw); // throws on garbage; the caller shows the error badge
  const host = u.hostname.toLowerCase().replace(/\.$/, '');

  const qStart = raw.indexOf('?');
  if (qStart === -1) return raw;
  const hashAt = raw.indexOf('#', qStart);
  const head = raw.slice(0, qStart);
  const query = raw.slice(qStart + 1, hashAt === -1 ? undefined : hashAt);
  const tail = hashAt === -1 ? '' : raw.slice(hashAt);

  const kept = query.split('&').filter((pair) => {
    if (!pair) return false;
    const rawKey = pair.split('=')[0];
    let key = rawKey;
    try { key = decodeURIComponent(rawKey); } catch (e) { /* keep the raw form */ }
    key = key.toLowerCase();
    if (rules && (rules.tracking || rules.never_strip)) return !ruleHits(key, host, rules);
    return !FALLBACK.some((f) => (f instanceof RegExp ? f.test(key) : f === key));
  });

  return kept.length ? head + '?' + kept.join('&') + tail : head + tail;
}

// The badge shows only when pinned (fresh installs are not), so failures also raise a notification.
async function badge(text, colour) {
  try {
    await chrome.action.setBadgeBackgroundColor({ color: colour });
    await chrome.action.setBadgeText({ text });
  } catch (_) { /* no action surface: not fatal */ }
}

// No "notifications" permission on purpose: it would add an install warning for a failure path.
async function notify(message) {
  try {
    await chrome.notifications?.create({
      type: 'basic', iconUrl: 'icons/128.png', title: 'Corpberry Link', message,
    });
  } catch (_) { /* not granted; the badge already showed "!" */ }
}
