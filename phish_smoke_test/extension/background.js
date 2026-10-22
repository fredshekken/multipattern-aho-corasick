// Fallback path: some sites (for example Facebook) can block a page script from
// calling the local backend. The extension's background script is not subject to
// the page's rules, so content.js asks it to make the call instead.
const BACKEND_URL = "http://127.0.0.1:8000/scan";

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!msg || msg.type !== "phishshield-scan" || typeof msg.text !== "string") return;

  fetch(BACKEND_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ text: msg.text })
  })
    .then((res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return res.json();
    })
    .then((data) => sendResponse({ ok: true, data: data }))
    .catch((err) => sendResponse({ ok: false, error: String(err) }));

  return true; // keep the channel open for the async response
});