// Registered at top level so it is listening by the time createDocument() resolves in sw.js.
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.target !== 'offscreen' || msg.type !== 'copy') return false;

  const el = document.getElementById('sink');
  let ok = false;
  try {
    el.value = msg.text;
    el.select();
    ok = document.execCommand('copy');
  } catch (e) {
    ok = false;
  } finally {
    el.value = '';
  }
  // Reply, unlike Google's sample: this ack is the badge's only signal for a tick or a cross.
  sendResponse({ ok });
  return true;
});
