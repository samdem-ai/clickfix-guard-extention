// End-to-end test in real browsers: loads the unpacked extension, serves the
// lure / benign pages in test/pages, clicks like a user and checks what lands
// on the clipboard, whether the warning appears and what the popup logs.
//
//   node test/e2e.mjs            # every browser found
//   node test/e2e.mjs chromium   # or: firefox
//
// Chromium is driven over CDP (--load-extension), Firefox over WebDriver BiDi
// (webExtension.install). Override binaries with CHROME=... / FIREFOX=...
// Uses only Node built-ins (global WebSocket, Node >= 22).
import { execFileSync, spawn } from "node:child_process";
import { createServer } from "node:http";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
const PAGES = join(ROOT, "test", "pages");
// EXTENSION=/path/to/unpacked tests a built package instead of the repo folder.
// The repo folder is the Chrome build; Firefox installs the built .xpi.
const EXT = process.env.EXTENSION || ROOT;
function firefoxPackage() {
  if (process.env.EXTENSION) return { type: "path", path: process.env.EXTENSION };
  execFileSync("python3", [join(ROOT, "tools", "build.py")], { stdio: "ignore" });
  const version = JSON.parse(readFileSync(join(ROOT, "manifest.json"), "utf8")).version;
  return { type: "archivePath", path: join(ROOT, "dist", `clickfix-guard-${version}-firefox.xpi`) };
}
const GECKO_ID = JSON.parse(readFileSync(join(ROOT, "manifest.firefox.json"), "utf8")).browser_specific_settings.gecko.id;
const NOTICE_PREFIX = "# ClickFix Guard blocked";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitFor(fn, ms = 5000) {
  const end = Date.now() + ms;
  let v;
  while (Date.now() < end) {
    try { v = await fn(); } catch (_) { v = null; }
    if (v) return v;
    await sleep(100);
  }
  return v;
}

// --- JSON-over-WebSocket RPC (shared by CDP and BiDi) ------------------------
async function rpc(url) {
  const ws = new WebSocket(url);
  await new Promise((r, j) => { ws.onopen = r; ws.onerror = () => j(new Error("ws connect failed: " + url)); });
  let nextId = 1;
  const pending = new Map();
  const listeners = new Set();
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.id && pending.has(msg.id)) {
      const { resolve, reject } = pending.get(msg.id);
      pending.delete(msg.id);
      if (msg.error) reject(new Error(typeof msg.error === "string" ? `${msg.error}: ${msg.message}` : msg.error.message));
      else resolve(msg.result);
    } else {
      for (const l of listeners) l(msg);
    }
  };
  return {
    send(method, params = {}, extra = {}) {
      return new Promise((resolve, reject) => {
        const id = nextId++;
        pending.set(id, { resolve, reject });
        ws.send(JSON.stringify({ id, method, params, ...extra }));
      });
    },
    on: (l) => listeners.add(l),
    close: () => ws.close(),
  };
}

function launch(bin, args, pattern) {
  const proc = spawn(bin, args, { stdio: ["ignore", "pipe", "pipe"] });
  const url = new Promise((resolve, reject) => {
    let buf = "";
    const t = setTimeout(() => reject(new Error(`${bin} did not start:\n${buf.slice(-2000)}`)), 30000);
    const onData = (d) => {
      buf += d;
      const m = buf.match(pattern);
      if (m) { clearTimeout(t); resolve(m[1]); }
    };
    proc.stdout.on("data", onData);
    proc.stderr.on("data", onData);
    proc.on("exit", (code) => reject(new Error(`${bin} exited (${code}):\n${buf.slice(-2000)}`)));
  });
  return { proc, url };
}

// --- Chromium driver (CDP) ------------------------------------------------------
async function chromium(bin) {
  const profile = mkdtempSync(join(tmpdir(), "cfg-chromium-"));
  const { proc, url } = launch(bin, [
    "--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`,
    `--load-extension=${EXT}`, `--disable-extensions-except=${EXT}`,
    "--disable-features=DisableLoadExtensionCommandLineSwitch",
    "--no-first-run", "--no-default-browser-check", "--disable-gpu", "about:blank",
  ], /DevTools listening on (ws:\/\/\S+)/);
  const c = await rpc(await url);
  const frames = new Map(); // page session -> [iframe sessions]
  c.on((m) => {
    if (m.method === "Target.attachedToTarget" && m.params.targetInfo.type === "iframe") {
      if (!frames.has(m.sessionId)) frames.set(m.sessionId, []);
      frames.get(m.sessionId).push(m.params.sessionId);
    }
  });
  const send = (method, params, sessionId) => c.send(method, params, sessionId ? { sessionId } : {});
  const evaluate = async (sessionId, expression) => {
    const r = await send("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true, userGesture: true }, sessionId);
    if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || "eval failed");
    return r.result.value;
  };

  const sw = await waitFor(async () => (await send("Target.getTargets")).targetInfos
    .find((t) => t.type === "service_worker" && t.url.endsWith("/src/background.js")), 10000);
  if (!sw) throw new Error("extension not loaded (does this Chromium allow --load-extension?)");
  const base = sw.url.replace(/\/src\/background\.js$/, ""); // URL.origin is "null" for chrome-extension:

  async function attach(targetId) {
    const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
    await send("Runtime.enable", {}, sessionId);
    await send("Emulation.setFocusEmulationEnabled", { enabled: true }, sessionId).catch(() => {});
    return sessionId;
  }

  return {
    name: "chromium",
    async grant(origins) {
      for (const origin of origins) {
        await send("Browser.grantPermissions", { origin, permissions: ["clipboardReadWrite", "clipboardSanitizedWrite"] });
      }
    },
    async open(pageUrl) {
      const { targetId } = await send("Target.createTarget", { url: "about:blank" });
      const s = await attach(targetId);
      await send("Page.enable", {}, s);
      await send("Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: false, flatten: true }, s);
      const loaded = new Promise((r) => c.on((m) => { if (m.method === "Page.loadEventFired" && m.sessionId === s) r(); }));
      await send("Page.navigate", { url: pageUrl }, s);
      await loaded;
      return {
        eval: (expr) => evaluate(s, expr),
        async frameEval(expr) {
          const fs = (await waitFor(() => frames.get(s)))?.[0];
          if (!fs) throw new Error("no out-of-process iframe");
          await send("Emulation.setFocusEmulationEnabled", { enabled: true }, fs).catch(() => {});
          return evaluate(fs, expr);
        },
        async clickAt(x, y) {
          for (const type of ["mousePressed", "mouseReleased"]) {
            await send("Input.dispatchMouseEvent", { type, x, y, button: "left", clickCount: 1 }, s);
          }
        },
        async pressCopy() {
          for (const type of ["rawKeyDown", "keyUp"]) {
            await send("Input.dispatchKeyEvent", { type, key: "c", code: "KeyC", windowsVirtualKeyCode: 67, modifiers: 2,
              commands: type === "rawKeyDown" ? ["copy"] : [] }, s);
          }
        },
        // Headless Chromium keeps every tab "visible" and focused, so leaving is
        // simulated: drop focus emulation, then deliver the window blur.
        async leave() {
          await send("Emulation.setFocusEmulationEnabled", { enabled: false }, s);
          await evaluate(s, "window.dispatchEvent(new FocusEvent('blur')), true");
        },
        async screenshot(file) {
          await send("Emulation.setDeviceMetricsOverride", { width: 1100, height: 760, deviceScaleFactor: 1, mobile: false }, s);
          const { data } = await send("Page.captureScreenshot", { format: "png" }, s);
          writeFileSync(file, Buffer.from(data, "base64"));
        },
        close: () => send("Target.closeTarget", { targetId }),
      };
    },
    async openExtensionPage(path) {
      // Extension pages can't be reached with Page.navigate; let the extension open the tab.
      const swSession = await attach(sw.targetId);
      const pageUrl = `${base}/${path}`;
      await evaluate(swSession, `chrome.tabs.create({ url: ${JSON.stringify(pageUrl)} }).then(() => true)`);
      const t = await waitFor(async () => (await send("Target.getTargets")).targetInfos
        .find((x) => x.type === "page" && x.url.startsWith(pageUrl)), 10000);
      if (!t) throw new Error("extension page did not open");
      const s = await attach(t.targetId);
      await waitFor(() => evaluate(s, "document.readyState === 'complete'"));
      return { eval: (expr) => evaluate(s, expr), close: () => send("Target.closeTarget", { targetId: t.targetId }) };
    },
    async quit() {
      c.close();
      proc.kill();
      await sleep(300);
      rmSync(profile, { recursive: true, force: true });
    },
  };
}

// --- Firefox driver (WebDriver BiDi) --------------------------------------------
async function firefox(bin) {
  const profile = mkdtempSync(join(tmpdir(), "cfg-firefox-"));
  const uuid = "6b1d2a5e-6f3c-4d57-9c1e-0c1f9a7e2b10";
  writeFileSync(join(profile, "user.js"), [
    // Let tests read the clipboard without Firefox's "Paste" confirmation menu.
    `user_pref("dom.events.testing.asyncClipboard", true);`,
    // Fixed moz-extension:// UUID so the popup URL is predictable.
    `user_pref("extensions.webextensions.uuids", ${JSON.stringify(JSON.stringify({ [GECKO_ID]: uuid }))});`,
    `user_pref("browser.shell.checkDefaultBrowser", false);`,
    `user_pref("datareporting.policy.dataSubmissionEnabled", false);`,
    `user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);`,
    `user_pref("browser.startup.homepage_override.mstone", "ignore");`,
  ].join("\n"));
  const { proc, url } = launch(bin, ["--headless", "--remote-debugging-port=0", "--profile", profile, "--no-remote"],
    /WebDriver BiDi listening on (ws:\/\/\S+)/);
  const c = await rpc((await url).replace(/\/?$/, "/session"));
  await c.send("session.new", { capabilities: {} });
  await c.send("webExtension.install", { extensionData: firefoxPackage() });

  const evaluate = async (context, expression) => {
    const r = await c.send("script.evaluate", {
      expression, target: { context }, awaitPromise: true, userActivation: true, resultOwnership: "none",
    });
    if (r.type === "exception") throw new Error(r.exceptionDetails.text);
    return unwrap(r.result);
  };

  async function newTab(pageUrl) {
    const { context } = await c.send("browsingContext.create", { type: "tab" });
    await c.send("browsingContext.navigate", { context, url: pageUrl, wait: "complete" });
    return context;
  }

  return {
    name: "firefox",
    async grant() { /* covered by dom.events.testing.asyncClipboard */ },
    async open(pageUrl) {
      const context = await newTab(pageUrl);
      return {
        eval: (expr) => evaluate(context, expr),
        async frameEval(expr) {
          const child = await waitFor(async () => {
            const { contexts } = await c.send("browsingContext.getTree", { root: context });
            return contexts[0]?.children?.find((k) => k.url.includes("/captcha.html"))?.context;
          });
          if (!child) throw new Error("iframe context not found");
          return evaluate(child, expr);
        },
        async leave() { /* opening another tab really blurs and hides this one */ },
        async clickAt(x, y) {
          await c.send("input.performActions", { context, actions: [{ type: "pointer", id: "mouse", actions: [
            { type: "pointerMove", x: Math.round(x), y: Math.round(y) }, { type: "pointerDown", button: 0 }, { type: "pointerUp", button: 0 }] }] });
        },
        async pressCopy() {
          await c.send("input.performActions", { context, actions: [{ type: "key", id: "kbd", actions: [
            { type: "keyDown", value: "\uE009" }, { type: "keyDown", value: "c" },
            { type: "keyUp", value: "c" }, { type: "keyUp", value: "\uE009" }] }] });
        },
        close: () => c.send("browsingContext.close", { context }),
      };
    },
    // BiDi refuses to navigate to moz-extension:// pages. The background relay
    // is still covered: the iframe case only passes if it forwards the warning.
    openExtensionPage: null,
    async quit() {
      await c.send("session.end").catch(() => {});
      c.close();
      proc.kill();
      await sleep(500);
      rmSync(profile, { recursive: true, force: true });
    },
  };
}

// BiDi remote values -> plain JS.
function unwrap(v) {
  if (!v) return v;
  switch (v.type) {
    case "undefined": case "null": return null;
    case "string": case "number": case "boolean": return v.value;
    case "array": return v.value.map(unwrap);
    case "object": return Object.fromEntries(v.value.map(([k, x]) => [typeof k === "string" ? k : unwrap(k), unwrap(x)]));
    default: return v.value ?? null;
  }
}

// --- test cases (browser-independent) -------------------------------------------
const DEMO = join(ROOT, "demo");
const TYPES = { html: "text/html; charset=utf-8", css: "text/css", js: "text/javascript", png: "image/png" };
const server = createServer((req, res) => {
  const path = new URL(req.url, "http://x").pathname;
  // /demo/... serves the public demo site; everything else the test pages.
  const [base, rel] = path.startsWith("/demo/") ? [DEMO, path.slice(5)] : [PAGES, path];
  const file = normalize(join(base, rel));
  if (!file.startsWith(base) || !existsSync(file)) { res.writeHead(404).end(); return; }
  res.writeHead(200, { "content-type": TYPES[file.split(".").pop()] || "application/octet-stream" }).end(readFileSync(file));
});
await new Promise((r) => server.listen(0, "127.0.0.1", r));
const PORT = server.address().port;
const BASE = `http://localhost:${PORT}`;

const clickJs = (sel) => `(document.querySelector(${JSON.stringify(sel)}).focus(), document.querySelector(${JSON.stringify(sel)}).click(), true)`;
const CLIP = "navigator.clipboard.readText()";
const RESET = "navigator.clipboard.writeText('sentinel').then(() => true)";
const OVERLAY = "document.querySelector('clickfix-guard-alert')?.dataset.verdict || null";

async function runCases(b, results) {
  const check = (name, cond, info) => {
    results.push(!!cond);
    console.log(`${cond ? "PASS" : "FAIL"}  [${b.name}] ${name}${cond ? "" : "  -> " + JSON.stringify(info)}`);
  };
  await b.grant([BASE, `http://127.0.0.1:${PORT}`, ...(process.env.DEMO_URL ? [new URL(process.env.DEMO_URL).origin] : [])]);

  for (const [name, page, sel] of [
    ["fake CAPTCHA (clipboard.writeText)", "captcha.html", "#robot"],
    ["hidden textarea (execCommand)", "exec.html", "#robot"],
    ["copy-event hijack (setData)", "setdata.html", "#fix"],
  ]) {
    const p = await b.open(`${BASE}/${page}`);
    await p.eval(RESET);
    await p.eval(clickJs(sel));
    const verdict = await waitFor(() => p.eval(OVERLAY));
    const clip = await p.eval(CLIP);
    check(`${name}: payload replaced by notice`, clip?.startsWith(NOTICE_PREFIX), { clip });
    check(`${name}: block warning shown`, verdict === "block", { verdict });
    // SCREENSHOT=path.png captures the warning UI (Chromium) for the README.
    if (process.env.SCREENSHOT && p.screenshot && page === "captcha.html") await p.screenshot(process.env.SCREENSHOT);
    await p.close();
  }

  {
    const p = await b.open(`${BASE}/iframe.html`);
    await p.eval(RESET);
    await waitFor(() => p.frameEval("document.readyState === 'complete' && !!document.querySelector('#robot')"));
    await p.frameEval("(window.focus(), true)");
    await p.frameEval(clickJs("#robot"));
    const frameResult = await waitFor(() => p.frameEval("window.copyResult || null"));
    const verdict = await waitFor(() => p.eval(OVERLAY));
    const clip = await p.eval(CLIP);
    check("cross-origin iframe lure: payload replaced", clip?.startsWith(NOTICE_PREFIX), { clip, frameResult });
    check("cross-origin iframe lure: warning shown in top page", verdict === "block", { verdict });
    await p.close();
  }

  {
    const p = await b.open(`${BASE}/benign.html`);
    await p.eval(RESET);
    await p.eval(clickJs("#copy-npm"));
    await waitFor(() => p.eval("window.copyResult"));
    await sleep(300);
    let clip = await p.eval(CLIP);
    check("benign npm command copied unchanged", clip === "npm install --save express", { clip });
    check("benign npm command: no warning", (await p.eval(OVERLAY)) === null, {});
    await p.eval(clickJs("#copy-docker"));
    const verdict = await waitFor(() => p.eval(OVERLAY));
    clip = await p.eval(CLIP);
    check("installer one-liner copied unchanged", clip === "curl -fsSL https://get.docker.com | sh", { clip });
    check("visible command + Copy button: no warning", verdict === null, { verdict });
    // Not armed: leaving the browser must not touch the clipboard.
    const q = await b.open(`${BASE}/blank.html`);
    await p.leave();
    await sleep(800);
    clip = await q.eval(CLIP);
    check("leaving after a benign copy keeps the clipboard", clip === "curl -fsSL https://get.docker.com | sh", { clip });
    await q.close();
    await p.close();
  }

  // The user selects text and presses Ctrl+C themselves.
  {
    const p = await b.open(`${BASE}/usercopy.html`);
    const select = (id) => `(getSelection().selectAllChildren(document.getElementById(${JSON.stringify(id)})), true)`;
    await p.eval(RESET);
    await p.eval(select("good"));
    await p.pressCopy();
    let clip = await waitFor(async () => { const c = await p.eval(CLIP); return c !== "sentinel" ? c : null; });
    check("user Ctrl+C of a normal command: copied unchanged", clip === "git clone https://github.com/samdem-ai/portfolio.git", { clip });
    check("user Ctrl+C of a normal command: no warning", (await p.eval(OVERLAY)) === null, {});
    await p.eval(select("bad"));
    await p.pressCopy();
    const verdict = await waitFor(() => p.eval(OVERLAY));
    clip = await p.eval(CLIP);
    check("user Ctrl+C of a lure command: replaced by notice", clip.startsWith(NOTICE_PREFIX), { clip });
    check("user Ctrl+C of a lure command: block warning", verdict === "block", { verdict });
    await p.close();
  }

  // Risky command behind a misleading button: warned, then scrubbed on leaving.
  {
    const p = await b.open(`${BASE}/guard.html`);
    await p.eval(RESET);
    await p.eval(clickJs("#go"));
    const verdict = await waitFor(() => p.eval(OVERLAY));
    const before = await p.eval(CLIP);
    check("misleading button: warning toast", verdict === "warn", { verdict });
    check("misleading button: command still copied", before.startsWith("powershell -ExecutionPolicy"), { before });
    const q = await b.open(`${BASE}/blank.html`); // user switches away (Win+R / Terminal)
    await p.leave();
    const clip = await waitFor(async () => {
      const c = await q.eval(CLIP);
      return c.startsWith(NOTICE_PREFIX) ? c : null;
    });
    check("leaving the browser scrubs the risky command", !!clip, { clip: await q.eval(CLIP) });
    await q.close();
    await p.close();
  }

  // Looks honest at copy time; Win+R instructions appear afterwards.
  {
    const p = await b.open(`${BASE}/delayed.html`);
    await p.eval(RESET);
    await p.eval(clickJs("#copy"));
    const verdict = await waitFor(() => p.eval("document.querySelector('clickfix-guard-alert[data-verdict=block]') ? 'block' : null"), 8000);
    const clip = await waitFor(async () => {
      const c = await p.eval(CLIP);
      return c.startsWith(NOTICE_PREFIX) ? c : null;
    });
    check("instructions shown after copy: escalated to block", verdict === "block", { verdict });
    check("instructions shown after copy: clipboard scrubbed", !!clip, { clip: await p.eval(CLIP) });
    await p.close();
  }

  // The public demo site: real mouse clicks into each simulated lure frame.
  {
    // DEMO_URL=https://… runs this case against the deployed site instead.
    const p = await b.open(process.env.DEMO_URL || `${BASE}/demo/index.html`);
    for (const [scenario, sel, want] of [
      ["captcha", "#robot", "blocked"], ["hidden", "#verify", "blocked"], ["terminal", "#fix", "blocked"],
      ["delayed", "#copy", "blocked"], ["benign", "#copy", "fine"],
    ]) {
      await p.eval("document.querySelector('clickfix-guard-alert')?.remove(), true"); // user closes the previous warning
      const pt = await waitFor(() => p.eval(`(() => {
        const card = document.querySelector('[data-scenario=${scenario}]');
        const f = card.querySelector('iframe');
        const el = f.contentDocument && f.contentDocument.querySelector(${JSON.stringify(sel)});
        if (!el) return null;
        card.scrollIntoView({ block: "center" });
        const fr = f.getBoundingClientRect(), r = el.getBoundingClientRect();
        return { x: fr.left + r.left + r.width / 2, y: fr.top + r.top + r.height / 2 };
      })()`));
      await sleep(200);
      if (process.env.DEBUG_DEMO) await p.eval(`(() => { const d = document.querySelector('[data-scenario=${scenario}] iframe').contentDocument;
        window.__dbg = []; d.addEventListener('clickfix-guard:detection', (e) => __dbg.push(JSON.parse(e.detail).verdict)); return true; })()`);
      await p.clickAt(pt.x, pt.y);
      if (process.env.DEBUG_DEMO) { await sleep(1500); console.log("DEBUG", scenario, JSON.stringify(await p.eval("window.__dbg")), JSON.stringify(await p.eval("navigator.clipboard.readText()").catch((e) => String(e)))); }
      const got = await waitFor(() => p.eval(`(() => {
        const r = document.querySelector('[data-scenario=${scenario}] .result');
        const k = ["blocked", "warned", "exposed", "fine"].find((c) => r.classList.contains(c));
        return k || null;
      })()`), 10000);
      check(`demo site: ${scenario} -> ${want}`, got === want, { got });
    }
    check("demo site: status shows extension active", (await p.eval("document.getElementById('status').classList.contains('on')")) === true, {});
    await p.close();
  }

  if (!b.openExtensionPage) {
    console.log(`SKIP  [${b.name}] popup checks (automation cannot open extension pages)`);
  } else {
    const p = await b.openExtensionPage("popup/popup.html");
    const n = await waitFor(async () => {
      const k = await p.eval("document.querySelectorAll('#log li').length");
      return k >= 5 ? k : null;
    });
    const blocked = await p.eval("document.getElementById('blocked').textContent");
    check("popup lists logged detections", n >= 5, { n });
    const cleared = await p.eval("document.getElementById('scrubbed').textContent");
    check("popup counts blocks", Number(blocked) >= 4, { blocked });
    check("popup counts cleared clipboards", Number(cleared) >= 2, { cleared });
    await p.close();
  }
}

const DRIVERS = {
  chromium: [chromium, process.env.CHROME || ["/usr/bin/chromium", "/usr/bin/chromium-browser"].find(existsSync)],
  firefox: [firefox, process.env.FIREFOX || ["/usr/bin/firefox", "/usr/bin/firefox-esr"].find(existsSync)],
};
const wanted = process.argv[2] ? [process.argv[2]] : Object.keys(DRIVERS);
const all = [];
for (const name of wanted) {
  const [make, bin] = DRIVERS[name] || [];
  if (!make) { console.error(`unknown browser ${name}`); process.exit(1); }
  if (!bin) { console.log(`SKIP  [${name}] browser not found`); continue; }
  let b;
  try {
    b = await make(bin);
    await runCases(b, all);
  } catch (e) {
    console.log(`FAIL  [${name}] ${e.message}`);
    all.push(false);
  } finally {
    if (b) await b.quit();
  }
}
server.close();
const failed = all.filter((ok) => !ok).length;
console.log(`\n${all.length - failed}/${all.length} checks passed`);
process.exit(failed || !all.length ? 1 : 0);
