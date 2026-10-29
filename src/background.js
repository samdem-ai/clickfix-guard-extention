/*
 * ClickFix Guard background. Runs as a service worker in Chrome and as an
 * event page in Firefox (same file, see manifest "background").
 *
 * Keeps a local detection log, sets the per-tab badge and asks the tab's top
 * frame to show the warning (detections can come from any iframe).
 */
"use strict";

const api = globalThis.browser ?? globalThis.chrome;
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

api.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || msg.type !== "detection" || !sender.tab || sender.id !== api.runtime.id) return;
  const d = msg.detection;
  if (!d || (d.verdict !== "block" && d.verdict !== "warn")) return;
  const tabId = sender.tab.id;
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
