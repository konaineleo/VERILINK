// VERIKLIK content script: asks Detect / Direct / Cancel on ordinary link clicks.
(() => {
  const FRONTEND_ORIGIN = "http://localhost:5500"; // keep in sync with background.js
  if (location.origin === FRONTEND_ORIGIN) return; // never intercept inside VERIKLIK
  let open = false;

  document.addEventListener("click", (e) => {
    if (open || e.defaultPrevented || e.button !== 0 || e.ctrlKey || e.metaKey ||
        e.shiftKey || e.altKey || !e.isTrusted) return;
    const a = e.target instanceof Element ? e.target.closest("a[href]") : null;
    if (!a || a.hasAttribute("download")) return;
    let u; try { u = new URL(a.href); } catch { return; }
    if (u.protocol !== "http:" && u.protocol !== "https:") return;
    if (u.origin === location.origin && u.pathname === location.pathname && u.search === location.search) return;
    e.preventDefault(); e.stopPropagation();
    show(u.href, a.target === "_blank");
  }, true);

  function show(url, newTab) {
    open = true;
    const host = document.createElement("div");
    const root = host.attachShadow({ mode: "closed" });
    const st = document.createElement("style");
    st.textContent = `
      .wrap{position:fixed;inset:0;z-index:2147483647;background:rgba(48,52,59,.35);display:flex;align-items:center;justify-content:center;font:14px/1.5 Inter,system-ui,sans-serif}
      .box{background:#fff;color:#30343b;border:1px solid #e5e5e2;border-radius:6px;padding:20px;width:min(420px,90vw);box-shadow:0 4px 16px rgba(0,0,0,.12)}
      h2{margin:0 0 4px;font-size:16px;color:#873d46}
      .u{margin:8px 0;padding:8px;background:#fafaf7;border:1px solid #e5e5e2;border-radius:4px;word-break:break-all;font-size:12px}
      p{margin:0 0 12px;color:#737780;font-size:12px}
      .r{display:flex;gap:8px;justify-content:flex-end}
      button{font:inherit;padding:7px 14px;border-radius:4px;border:1px solid #e5e5e2;background:#fff;color:#30343b;cursor:pointer}
      button:focus-visible{outline:2px solid #873d46;outline-offset:2px}
      .p{background:#873d46;border-color:#873d46;color:#fff}`;
    const wrap = document.createElement("div"); wrap.className = "wrap";
    const box = document.createElement("div"); box.className = "box";
    box.setAttribute("role", "dialog"); box.setAttribute("aria-label", "VERIKLIK");
    const h = document.createElement("h2"); h.textContent = "VERIKLIK";
    const u = document.createElement("div"); u.className = "u";
    u.textContent = url.length > 90 ? url.slice(0, 87) + "…" : url; // text only, never HTML
    const p = document.createElement("p");
    p.textContent = "Direct opens the link without scanning. An unscanned link is not verified as safe.";
    const r = document.createElement("div"); r.className = "r";
    const mk = (label, cls, fn) => { const b = document.createElement("button"); b.textContent = label; if (cls) b.className = cls; b.onclick = fn; return b; };
    const esc = (ev) => { if (ev.key === "Escape") close(); };
    const close = () => { host.remove(); open = false; document.removeEventListener("keydown", esc, true); };
    document.addEventListener("keydown", esc, true);
    r.append(
      mk("Cancel", "", close),
      mk("Direct", "", () => { close(); newTab ? window.open(url, "_blank", "noopener") : (location.href = url); }),
      mk("Detect", "p", () => { close(); chrome.runtime.sendMessage({ type: "veriklik-detect", url }); })
    );
    box.append(h, u, p, r); wrap.append(box); root.append(st, wrap);
    document.documentElement.append(host);
    r.lastChild.focus();
  }
})();
