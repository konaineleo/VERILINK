// VERIKLIK service worker. Opens the scanner only after the user chooses Detect.
const FRONTEND_URL = "https://veriklik.vercel.app/"; // change for production
chrome.runtime.onMessage.addListener((msg, sender) => {
  if (msg?.type !== "veriklik-detect" || sender.id !== chrome.runtime.id) return;
  try {
    const u = new URL(msg.url);
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    chrome.tabs.create({ url: FRONTEND_URL + "?url=" + encodeURIComponent(u.href) });
  } catch (e) { /* ignore invalid URLs */ }
});
