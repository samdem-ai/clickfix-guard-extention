/*
 * ClickFix Guard background. Runs as a service worker in Chrome and as an
 * event page in Firefox (same file, see manifest "background").
 *
 * Keeps a local detection log, sets the per-tab badge and asks the tab's top
 * frame to show the warning (detections can come from any iframe).
 */
"use strict";

const api = globalThis.browser ?? globalThis.chrome;
// Firefox loads analyzer.js before this file (manifest "scripts"); the Chrome
// service worker pulls it in here. Needed for the clipboard notice text.
if (!globalThis.ClickFixAnalyzer && typeof importScripts === "function") importScripts("analyzer.js");
const { notice } = globalThis.ClickFixAnalyzer;
const LOG_KEY = "log";
const STATS_KEY = "stats";
const LOG_MAX = 100;

// Serialise storage updates so concurrent detections don't overwrite each other.
let queue = Promise.resolve();
function record(entry) {
  queue = queue.then(async () => {
    const data = await api.storage.local.get([LOG_KEY, STATS_KEY]);
    const log = Array.isArray(data[LOG_KEY]) ? data[LOG_KEY] : [];
    const stats = data[STATS_KEY] || { block: 0, warn: 0 };
    log.unshift(entry);
    stats[entry.verdict] = (stats[entry.verdict] || 0) + 1;
    await api.storage.local.set({ [LOG_KEY]: log.slice(0, LOG_MAX), [STATS_KEY]: stats });
  }).catch(() => {});
  return queue;
}

async function bumpBadge(tabId, verdict) {
  const key = `badge:${tabId}`;
  // Session storage survives service-worker restarts (Chrome) and is cleared with the browser.
  const store = api.storage.session || null;
  let n = 1;
  if (store) {
    const cur = await store.get(key);
    n = (cur[key] || 0) + 1;
    await store.set({ [key]: n });
  }
  await api.action.setBadgeText({ tabId, text: String(n) });
  await api.action.setBadgeBackgroundColor({ tabId, color: verdict === "block" ? "#c62828" : "#ef6c00" });
}

// --- Clipboard scrubbing --------------------------------------------------------
// Writes happen here, not in the page, because by the time we scrub the page has
// usually lost focus and user activation. Chrome needs an offscreen document;
// Firefox's background page can write directly with "clipboardWrite".
const OFFSCREEN_URL = "offscreen/offscreen.html";

async function ensureOffscreen() {
  if (api.runtime.getContexts) {
    const existing = await api.runtime.getContexts({ contextTypes: ["OFFSCREEN_DOCUMENT"] });
    if (existing.length) return;
  }
  try {
    await api.offscreen.createDocument({
      url: OFFSCREEN_URL,
      reasons: ["CLIPBOARD"],
      justification: "Replace a dangerous command on the clipboard with a harmless note.",
    });
  } catch (e) {
    if (!/single offscreen|already/i.test(String(e && e.message))) throw e;
  }
}

function copyWithTextarea(text) {
  const ta = document.createElement("textarea");
  ta.value = text;
  document.body.append(ta);
  ta.select();
  const ok = document.execCommand("copy");
  ta.remove();
  return ok;
}

async function writeClipboard(text) {
  if (api.offscreen) {
    await ensureOffscreen();
    return api.runtime.sendMessage({ type: "offscreen-copy", text });
  }
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (_) {
    return copyWithTextarea(text);
  }
}

function hostOf(url) {
  try { return new URL(url).hostname; } catch (_) { return ""; }
}

api.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || !sender.tab || sender.id !== api.runtime.id) return;
  const tabId = sender.tab.id;
  if (msg.type === "arm") {
    api.tabs.sendMessage(tabId, { type: "arm" }, { frameId: 0 }).catch(() => {});
    return;
  }
  if (msg.type === "scrub") {
    const host = hostOf(sender.url) || hostOf(sender.tab.url);
    writeClipboard(notice(host)).catch(() => {});
    record({
      ts: Date.now(), verdict: "scrub", score: 0, host, url: String(sender.tab.url || "").slice(0, 500),
      source: "clipboard scrub", reasons: [String(msg.reason || "risky command removed").slice(0, 160)], preview: "",
    });
    return;
  }
  if (msg.type !== "detection") return;
  const d = msg.detection;
  if (!d || (d.verdict !== "block" && d.verdict !== "warn")) return;
  record({
    ts: Date.now(),
    verdict: d.verdict,
    score: Number(d.score) || 0,
    host: String(d.host || "").slice(0, 200),
    url: String(sender.url || d.url || "").slice(0, 500),
    source: String(d.source || "").slice(0, 60),
    reasons: (d.reasons || []).slice(0, 6).map((r) => String(r.label || "").slice(0, 160)),
    preview: String(d.text || "").slice(0, 300),
  });
  bumpBadge(tabId, d.verdict).catch(() => {});
  api.tabs.sendMessage(tabId, { type: "show", detection: d }, { frameId: 0 }).catch(() => {});
});

api.tabs.onUpdated.addListener((tabId, info) => {
  if (info.status === "loading" && info.url) {
    api.action.setBadgeText({ tabId, text: "" }).catch(() => {});
    if (api.storage.session) api.storage.session.remove(`badge:${tabId}`).catch(() => {});
  }
});

api.tabs.onRemoved.addListener((tabId) => {
  if (api.storage.session) api.storage.session.remove(`badge:${tabId}`).catch(() => {});
});
