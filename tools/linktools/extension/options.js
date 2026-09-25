const $ = (id) => document.getElementById(id);

chrome.storage.sync.get(['apiKey', 'baseUrl']).then(({ apiKey, baseUrl }) => {
  $('key').value = apiKey || '';
  $('base').value = baseUrl || '';
});

// Mirrors resolveBase() in sw.js. Without this the page happily reported
// "Saved." for a server the worker then silently discarded, so a typo looked
// like it had worked and the key appeared not to function.
const DEFAULT_BASE = 'https://link.corpberry.com';
function acceptedBase(v) {
  if (!v) return { ok: true, why: '' };
  let u;
  try { u = new URL(v); } catch (e) { return { ok: false, why: 'Not a URL.' }; }
  if (u.origin === new URL(DEFAULT_BASE).origin) return { ok: true, why: '' };
  const dev = u.hostname === 'localhost' || u.hostname.endsWith('.localhost') ||
    u.hostname === '127.0.0.1' || u.hostname === '[::1]';
  if (u.protocol === 'http:' && dev) return { ok: true, why: '' };
  return { ok: false, why: 'Only ' + DEFAULT_BASE + ' or an http loopback address is accepted.' };
}

$('save').addEventListener('click', async () => {
  const base = $('base').value.trim().replace(/\/+$/, '');
  const verdict = acceptedBase(base);
  if (!verdict.ok) {
    $('status').style.color = '#c62828';
    $('status').textContent = verdict.why + ' Not saved.';
    return;
  }
  await chrome.storage.sync.set({ apiKey: $('key').value.trim(), baseUrl: base });
  $('status').style.color = '#2e7d32';
  $('status').textContent = 'Saved.';
  setTimeout(() => ($('status').textContent = ''), 2000);
});
