// End-to-end test: loads the unpacked extension into headless Chromium, serves
// the lure / benign pages in test/pages, clicks like a user and checks what
// actually lands on the clipboard and whether the warning appears.
//
// Run: node test/e2e.mjs   (needs a Chromium build that allows --load-extension;
// set CHROME=/path/to/chromium to override)
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { mkdtempSync, readFileSync, rmSync, existsSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const PAGES = join(ROOT, "test", "pages");
const CHROME = process.env.CHROME || ["/usr/bin/chromium", "/usr/bin/chromium-browser"].find(existsSync);
const NOTICE_PREFIX = "# ClickFix Guard blocked";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// --- static server -----------------------------------------------------------
const server = createServer((req, res) => {
  const file = normalize(join(PAGES, new URL(req.url, "http://x").pathname));
  if (!file.startsWith(PAGES) || !existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": "text/html; charset=utf-8" }).end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;

// --- browser -----------------------------------------------------------------
if (!CHROME) { console.error("No Chromium found; set CHROME="); process.exit(1); }
const profile = mkdtempSync(join(tmpdir(), "cfg-e2e-"));
const proc = spawn(CHROME, [
  "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
  `--load-extension=${ROOT}`, `--disable-extensions-except=${ROOT}`,
  "--disable-features=DisableLoadExtensionCommandLineSwitch",
  "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank",
], { stdio: ["ignore", "ignore", "pipe"] });

const wsUrl = await new Promise((resolve, reject) => {
  let buf = "";
  const t = setTimeout(() => reject(new Error("Chromium did not start:\n" + buf)), 20000);
  proc.stderr.on("data", (d) => {
    buf += d;
    const m = buf.match(/DevTools listening on (ws:\/\/\S+)/);
    if (m) { clearTimeout(t); resolve(m[1]); }
  });
});

// --- minimal CDP client --------------------------------------------------------
const ws = new WebSocket(wsUrl);
await new Promise((r, j) => { ws.onopen = r; ws.onerror = j; });
let nextId = 1;
const pending = new Map();
const listeners = [];
ws.onmessage = (m) => {
  const msg = JSON.parse(m.data);
  if (msg.id && pending.has(msg.id)) {
    const { resolve, reject } = pending.get(msg.id);
    pending.delete(msg.id);
    msg.error ? reject(new Error(msg.error.message)) : resolve(msg.result);
  } else if (msg.method) {
    for (const l of listeners) l(msg);
  }
};
const send = (method, params = {}, sessionId) => new Promise((resolve, reject) => {
  const id = nextId++;
  pending.set(id, { resolve, reject });
  ws.send(JSON.stringify({ id, method, params, sessionId }));
});
const waitEvent = (pred, ms = 10000) => new Promise((resolve, reject) => {
  const t = setTimeout(() => reject(new Error("timeout waiting for CDP event")), ms);
  const l = (msg) => { if (pred(msg)) { clearTimeout(t); listeners.splice(listeners.indexOf(l), 1); resolve(msg); } };
  listeners.push(l);
});
const evaluate = async (sessionId, expression) => {
  const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true }, sessionId);
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || "eval failed");
  return r.result.value;
};

// Wait for the extension's background service worker: proves the manifest loaded.
await send("Target.setDiscoverTargets", { discover: true });
const swTarget = await (async () => {
  for (let i = 0; i < 50; i++) {
    const { targetInfos } = await send("Target.getTargets");
    const sw = targetInfos.find((t) => t.type === "service_worker" && t.url.endsWith("/src/background.js"));
    if (sw) return sw;
    await sleep(200);
  }
  throw new Error("extension service worker not found: --load-extension may be unsupported by this browser");
})();
const extOrigin = swTarget.url.replace(/\/src\/background\.js$/, ""); // URL.origin is "null" for chrome-extension:

// Child frame sessions (out-of-process iframes) per page session.
const frames = new Map();
listeners.push((m) => {
  if (m.method === "Target.attachedToTarget" && m.params.targetInfo.type === "iframe") {
    if (!frames.has(m.sessionId)) frames.set(m.sessionId, []);
    frames.get(m.sessionId).push(m.params.sessionId);
  }
});

async function openPage(url) {
  const { targetId } = await send("Target.createTarget", { url: "about:blank" });
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  await send("Page.enable", {}, sessionId);
  await send("Runtime.enable", {}, sessionId);
  await send("Emulation.setFocusEmulationEnabled", { enabled: true }, sessionId);
  await send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, sessionId);
  const loaded = waitEvent((m) => m.method === "Page.loadEventFired" && m.sessionId === sessionId);
  await send("Page.navigate", { url }, sessionId);
  await loaded;
  return { targetId, sessionId };
}

async function click(sessionId, x, y) {
  for (const type of ["mousePressed", "mouseReleased"]) {
    await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 }, sessionId);
  }
}

async function rectCenter(sessionId, selector) {
  return evaluate(sessionId, `(() => { const r = document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();
    return { x: r.left + r.width / 2, y: r.top + r.height / 2 }; })()`);
}

async function clipboard(sessionId) {
  return evaluate(sessionId, "navigator.clipboard.readText()");
}

async function resetClipboard(sessionId) {
  // Our own write from the test, not a page script: use the clipboard of the
  // isolated harness via a plain value the analyzer allows.
  await evaluate(sessionId, "navigator.clipboard.writeText('sentinel')");
}

const overlay = (sessionId) => evaluate(sessionId, `document.querySelector('clickfix-guard-alert')?.dataset.verdict || null`);

async function waitFor(fn, ms = 4000) {
  const end = Date.now() + ms;
  let v;
  while (Date.now() < end) {
    v = await fn();
    if (v) return v;
    await sleep(100);
  }
  return v;
}

// --- cases ---------------------------------------------------------------------
const results = [];
function check(name, cond, info) {
  results.push({ name, ok: !!cond });
  console.log(`${cond ? "PASS" : "FAIL"}  ${name}${cond ? "" : "  -> " + JSON.stringify(info)}`);
}

const base = `http://localhost:${PORT}`;
for (const origin of [base, `http://127.0.0.1:${PORT}`]) {
  await send("Browser.grantPermissions", { origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] });
}

async function lureCase(name, page, selector) {
  const { targetId, sessionId } = await openPage(`${base}/${page}`);
  await resetClipboard(sessionId);
  const p = await rectCenter(sessionId, selector);
  await click(sessionId, p.x, p.y);
  const verdict = await waitFor(() => overlay(sessionId));
  const clip = await clipboard(sessionId);
  check(`${name}: payload replaced by notice`, clip.startsWith(NOTICE_PREFIX), { clip });
  check(`${name}: block warning shown`, verdict === "block", { verdict });
  await send("Target.closeTarget", { targetId });
}

await lureCase("fake CAPTCHA (clipboard.writeText)", "captcha.html", "#robot");
await lureCase("hidden textarea (execCommand)", "exec.html", "#robot");
await lureCase("copy-event hijack (setData)", "setdata.html", "#fix");

// Lure in a cross-origin iframe: click inside the frame, expect the warning on top.
{
  const { targetId, sessionId } = await openPage(`${base}/iframe.html`);
  const fs = (await waitFor(() => frames.get(sessionId), 5000) || [])[0];
  await resetClipboard(sessionId);
  let frameResult = null;
  if (fs) {
    await waitFor(() => evaluate(fs, "document.readyState === 'complete' && !!document.querySelector('#robot')"));
    // A real click focuses the frame; emulate that, then click with user activation.
    await send("Emulation.setFocusEmulationEnabled", { enabled: true }, fs).catch(() => {});
    await evaluate(fs, "window.focus(); document.querySelector('#robot').focus(); true");
    await evaluate(fs, "document.querySelector('#robot').click()");
    frameResult = await waitFor(() => evaluate(fs, "window.copyResult || null"));
  }
  const verdict = await waitFor(() => overlay(sessionId));
  const clip = await clipboard(sessionId);
  check("cross-origin iframe lure: payload replaced", clip.startsWith(NOTICE_PREFIX), { clip, oopif: !!fs, frameResult });
  check("cross-origin iframe lure: warning shown in top page", verdict === "block", { verdict });
  await send("Target.closeTarget", { targetId });
}

// Benign docs page.
{
  const { targetId, sessionId } = await openPage(`${base}/benign.html`);
  await resetClipboard(sessionId);
  let p = await rectCenter(sessionId, "#copy-npm");
  await click(sessionId, p.x, p.y);
  await sleep(500);
  let clip = await clipboard(sessionId);
  check("benign npm command copied unchanged", clip === "npm install --save express", { clip });
  check("benign npm command: no warning", (await overlay(sessionId)) === null, {});

  p = await rectCenter(sessionId, "#copy-docker");
  await click(sessionId, p.x, p.y);
  const verdict = await waitFor(() => overlay(sessionId));
  clip = await clipboard(sessionId);
  check("installer one-liner copied unchanged", clip === "curl -fsSL https://get.docker.com | sh", { clip });
  check("installer one-liner: non-blocking warning toast", verdict === "warn", { verdict });
  await send("Target.closeTarget", { targetId });
}

// Background log recorded the detections.
{
  const { sessionId } = await send("Target.attachToTarget", { targetId: swTarget.targetId, flatten: true });
  const stats = await evaluate(sessionId, "chrome.storage.local.get('stats').then((d) => d.stats)");
  check("background logged blocks and warnings", stats && stats.block >= 4 && stats.warn >= 1, { stats });
}

// Popup renders the log (opened as a tab by the extension itself).
{
  const popupUrl = `${extOrigin}/popup/popup.html`;
  const { sessionId: sw } = await send("Target.attachToTarget", { targetId: swTarget.targetId, flatten: true });
  const created = await evaluate(sw, `chrome.tabs.create({ url: ${JSON.stringify(popupUrl)} }).then((t) => [t.id, t.pendingUrl || t.url], (e) => String(e))`).catch((e) => String(e));
  const tgt = await waitFor(async () => (await send("Target.getTargets")).targetInfos
    .find((t) => t.type === "page" && t.url.startsWith(popupUrl)), 10000);
  if (!tgt) throw new Error("popup tab did not open: " + JSON.stringify((await send("Target.getTargets")).targetInfos.map((t) => [t.type, t.url])) + " create=" + JSON.stringify(created));
  const { targetId } = tgt;
  const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
  const n = await waitFor(() => evaluate(sessionId, "document.querySelectorAll('#log li').length"));
  const dbg = await evaluate(sessionId, "location.href + ' | ' + document.readyState + ' | ' + document.body.innerText.slice(0,200)").catch((e) => String(e));
  check("popup lists detections", n >= 5, { n, dbg });
  await send("Target.closeTarget", { targetId });
}

// --- teardown ------------------------------------------------------------------
ws.close();
proc.kill();
server.close();
await sleep(300);
rmSync(profile, { recursive: true, force: true });
const failed = results.filter((r) => !r.ok).length;
console.log(`\n${results.length - failed}/${results.length} checks passed`);
process.exit(failed ? 1 : 0);
