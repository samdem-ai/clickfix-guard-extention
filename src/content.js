/*
 * ClickFix Guard content script (isolated world).
 *
 * Receives detections from the page hook, forwards them to the background,
 * and renders the warning when the background sends one to the top frame.
 * Page-supplied strings are only ever inserted with textContent.
 */
(function () {
  "use strict";

  const api = globalThis.browser ?? globalThis.chrome;
  const EVENT = "clickfix-guard:detection";
  const TAG = "clickfix-guard-alert";
  const RATE_WINDOW_MS = 10000;
  const RATE_MAX = 5;
  let recent = [];

  function clean(d) {
    // The event is dispatched in the page, so treat its payload as untrusted.
    if (!d || (d.verdict !== "block" && d.verdict !== "warn")) return null;
    const str = (v, n) => (typeof v === "string" ? v.slice(0, n) : "");
    return {
      verdict: d.verdict,
      score: Number(d.score) || 0,
      reasons: (Array.isArray(d.reasons) ? d.reasons : []).slice(0, 12).map((r) => ({
        id: str(r && r.id, 40),
        label: str(r && r.label, 160),
        weight: Number(r && r.weight) || 0,
        match: str(r && r.match, 160),
      })),
      decoded: (Array.isArray(d.decoded) ? d.decoded : []).slice(0, 3).map((x) => str(x, 4000)),
      text: str(d.text, 4000),
      source: str(d.source, 60),
      host: location.hostname || str(d.host, 200),
      url: location.href.slice(0, 500),
    };
  }

  document.addEventListener(EVENT, (e) => {
    let d;
    try { d = clean(JSON.parse(e.detail)); } catch (_) { return; }
    if (!d) return;
    const now = Date.now();
    recent = recent.filter((t) => now - t < RATE_WINDOW_MS);
    if (recent.length >= RATE_MAX) return;
    recent.push(now);
    // If the background is unreachable (extension reloaded), still warn locally.
    const fallback = () => { if (window === window.top) show(d); };
    try {
      Promise.resolve(api.runtime.sendMessage({ type: "detection", detection: d })).catch(fallback);
    } catch (_) {
      fallback();
    }
  });

  if (window === window.top) {
    api.runtime.onMessage.addListener((msg) => {
      if (msg && msg.type === "show" && msg.detection) show(clean(msg.detection));
    });
  }

  // --- UI ---------------------------------------------------------------------

  const CSS = `
    :host { all: initial; }
    .backdrop { position: fixed; inset: 0; z-index: 2147483647; background: rgba(16, 6, 6, .78);
      display: flex; align-items: center; justify-content: center; padding: 16px;
      font: 15px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #1b1b1f; }
    .card { background: #fff; max-width: 640px; width: 100%; max-height: calc(100vh - 32px); overflow: auto;
      border-radius: 14px; box-shadow: 0 20px 60px rgba(0,0,0,.45); border-top: 6px solid #c62828; }
    .head { display: flex; gap: 12px; align-items: center; padding: 20px 22px 6px; }
    .icon { flex: none; width: 40px; height: 40px; border-radius: 50%; background: #c62828; color: #fff;
      display: grid; place-items: center; font-weight: 800; font-size: 24px; }
    h1 { font-size: 19px; margin: 0; line-height: 1.3; }
    .body { padding: 6px 22px 20px; }
    .site { color: #555; font-size: 13px; margin: 2px 0 12px; word-break: break-all; }
    .steps { background: #fff4e5; border-radius: 10px; padding: 12px 14px; margin: 12px 0; }
    .steps b { display: block; margin-bottom: 4px; }
    ul { margin: 6px 0 0; padding-left: 20px; }
    li { margin: 3px 0; }
    details { margin: 12px 0; }
    summary { cursor: pointer; font-weight: 600; }
    pre { white-space: pre-wrap; word-break: break-all; background: #16161a; color: #f2f2f2; padding: 10px 12px;
      border-radius: 8px; font: 12px/1.45 ui-monospace, Menlo, Consolas, monospace; max-height: 180px; overflow: auto; }
    .row { display: flex; flex-wrap: wrap; gap: 10px; justify-content: flex-end; margin-top: 16px; }
    button { font: inherit; border-radius: 8px; padding: 9px 16px; cursor: pointer; border: 1px solid #c9c9cf; background: #fff; }
    button.primary { background: #c62828; border-color: #c62828; color: #fff; font-weight: 600; }
    button.link { border: none; background: none; color: #555; text-decoration: underline; padding: 9px 4px; }
    button:focus-visible { outline: 3px solid #1565c0; outline-offset: 2px; }
    .toast { position: fixed; right: 16px; bottom: 16px; z-index: 2147483647; max-width: 380px; background: #fff;
      border-left: 5px solid #ef6c00; border-radius: 10px; box-shadow: 0 8px 30px rgba(0,0,0,.3); padding: 12px 14px;
      font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; color: #1b1b1f; }
    .toast .row { margin-top: 8px; }
    @media (prefers-color-scheme: dark) {
      .card, .toast { background: #1f1f24; color: #ececf1; }
      .site { color: #a9a9b3; }
      .steps { background: #3a2a12; }
      button { background: #2a2a31; color: #ececf1; border-color: #4a4a55; }
      button.link { background: none; color: #a9a9b3; }
    }
  `;

  function el(tag, attrs, ...children) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "on") for (const [ev, fn] of Object.entries(v)) n.addEventListener(ev, fn);
      else n.setAttribute(k, v);
    }
    for (const c of children) if (c != null) n.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return n;
  }

  function mount(verdict) {
    document.querySelectorAll(TAG).forEach((n) => n.remove());
    const hostEl = document.createElement(TAG);
    hostEl.dataset.verdict = verdict;
    const root = hostEl.attachShadow({ mode: "closed" });
    root.append(el("style", null, CSS));
    (document.documentElement || document).append(hostEl);
    return { hostEl, root };
  }

  function evidence(d) {
    return el("details", null,
      el("summary", null, "Technical details"),
      el("p", null, "Command the page tried to copy:"),
      el("pre", null, d.text),
      ...d.decoded.map((x) => el("div", null, el("p", null, "Decoded hidden payload:"), el("pre", null, x))),
      el("p", null, `Risk score ${d.score} (source: ${d.source})`));
  }

  function show(d) {
    if (!d || !document.documentElement) return;
    if (d.verdict === "warn") return showToast(d);
    const { hostEl, root } = mount("block");
    const close = () => hostEl.remove();
    const copyAnyway = async (ev) => {
      const ok = window.confirm(
        "Copy the original command anyway?\n\nOnly do this if you wrote this command yourself or fully understand it. " +
        "Legitimate websites do not ask you to verify you are human by running commands.");
      if (!ok) return;
      try {
        await navigator.clipboard.writeText(d.text);
        ev.target.textContent = "Copied";
      } catch (_) {
        ev.target.textContent = "Copy failed";
      }
    };
    const reasons = d.reasons.filter((r) => r.label).map((r) => el("li", null, r.label));
    const leave = el("button", { class: "primary", on: { click: () => { location.href = "about:blank"; } } }, "Leave this site");
    root.append(el("div", { class: "backdrop", role: "alertdialog", "aria-modal": "true", "aria-labelledby": "cfg-title" },
      el("div", { class: "card" },
        el("div", { class: "head" },
          el("div", { class: "icon", "aria-hidden": "true" }, "!"),
          el("h1", { id: "cfg-title" }, "This page tried to make you run a malicious command")),
        el("div", { class: "body" },
          el("div", { class: "site" }, d.host),
          el("p", null,
            "The page secretly copied a command to your clipboard. ClickFix Guard replaced it with a harmless note, " +
            "so nothing will run if you paste it."),
          el("div", { class: "steps" },
            el("b", null, "Do not follow the page's instructions."),
            "No real CAPTCHA, update or error fix asks you to press Win+R, open Terminal or paste text. " +
            "If you already pasted and ran a command from this page, disconnect from the internet and get help, " +
            "and change your passwords from another device."),
          reasons.length ? el("div", null, el("b", null, "Why it was blocked"), el("ul", null, ...reasons)) : null,
          evidence(d),
          el("div", { class: "row" },
            el("button", { class: "link", on: { click: copyAnyway } }, "Copy original anyway"),
            el("button", { on: { click: close } }, "Close"),
            leave)))));
    leave.focus();
    root.addEventListener("keydown", (e) => { if (e.key === "Escape") close(); });
  }

  function showToast(d) {
    if (document.querySelector(TAG + '[data-verdict="block"]')) return; // never hide a block behind a toast
    const { hostEl, root } = mount("warn");
    const timer = setTimeout(() => hostEl.remove(), 15000);
    const top = d.reasons.find((r) => r.label);
    root.append(el("div", { class: "toast", role: "status" },
      el("b", null, "Copied a command that runs code from the internet"),
      el("div", null, top ? top.label + ". " : "", "Only run it if you trust this site and meant to install something."),
      evidence(d),
      el("div", { class: "row" },
        el("button", { on: { click: () => { clearTimeout(timer); hostEl.remove(); } } }, "Dismiss"))));
  }
})();
