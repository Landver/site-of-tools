const $ = (id) => document.getElementById(id);

chrome.storage.sync.get(['apiKey', 'baseUrl']).then(({ apiKey, baseUrl }) => {
  $('key').value = apiKey || '';
  $('base').value = baseUrl || '';
});

$('save').addEventListener('click', async () => {
  await chrome.storage.sync.set({
    apiKey: $('key').value.trim(),
    baseUrl: $('base').value.trim().replace(/\/+$/, ''),
  });
  $('status').textContent = 'Saved.';
  setTimeout(() => ($('status').textContent = ''), 1500);
});
