"use strict";

const api = globalThis.browser ?? globalThis.chrome;
const $ = (id) => document.getElementById(id);

function item(entry) {
  const li = document.createElement("li");
  li.className = entry.verdict;
  const top = document.createElement("div");
  top.className = "top";
  const host = document.createElement("span");
  host.className = "host";
  const label = { block: "Blocked", warn: "Warned", scrub: "Clipboard cleared" }[entry.verdict] || entry.verdict;
  host.textContent = `${label} · ${entry.host || "unknown site"}`;
  const time = document.createElement("span");
  time.className = "time";
  time.textContent = new Date(entry.ts).toLocaleString();
  top.append(host, time);
  li.append(top);
  if (entry.reasons && entry.reasons[0]) {
    const r = document.createElement("div");
    r.className = "reason";
    r.textContent = entry.reasons[0];
    li.append(r);
  }
  if (entry.preview) {
    const code = document.createElement("code");
    code.textContent = entry.preview;
    li.append(code);
  }
  return li;
}

async function render() {
  const { log = [], stats = {} } = await api.storage.local.get(["log", "stats"]);
  $("blocked").textContent = stats.block || 0;
  $("warned").textContent = stats.warn || 0;
  $("scrubbed").textContent = stats.scrub || 0;
  $("log").replaceChildren(...log.slice(0, 30).map(item));
  $("empty").hidden = log.length > 0;
}

$("clear").addEventListener("click", async () => {
  await api.storage.local.set({ log: [], stats: { block: 0, warn: 0, scrub: 0 } });
  render();
});

render();
