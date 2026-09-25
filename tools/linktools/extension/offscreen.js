// Clipboard writer. Runs in the offscreen document; see offscreen.html for why
// this cannot use navigator.clipboard.
//
// The listener is registered at top-level script execution, which is what
// guarantees we are listening by the time createDocument() resolves in sw.js.
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
  // Answer, rather than the sample's fire-and-forget. This acknowledgement is
  // the only signal the badge has for showing a tick versus a cross, and it is
  // also what lets sw.js close the document only after the write has landed.
  sendResponse({ ok });
  return true;
});
