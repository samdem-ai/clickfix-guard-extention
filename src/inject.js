/*
 * ClickFix Guard page hook. Runs in the page's MAIN world at document_start,
 * before page scripts, so it can wrap the clipboard APIs a lure page uses:
 *
 *   navigator.clipboard.writeText / write      (async Clipboard API)
 *   DataTransfer.setData inside a copy event   (copy-event hijack)
 *   document.execCommand("copy")               (hidden textarea + select)
 *   plain selection copies (Ctrl+C on hidden or disguised text)
 *
 * A blocked command is never written; a harmless '#' notice is written instead
 * and the detection is handed to the isolated-world content script.
 */
(function () {
  "use strict";

  const A = globalThis.ClickFixAnalyzer;
  try { delete globalThis.ClickFixAnalyzer; } catch (_) { /* non-configurable */ }
  if (!A || typeof Clipboard === "undefined") return;

  const EVENT = "clickfix-guard:detection";
  const MAX_REPORT = 4000;

  // Capture originals before any page script can replace them.
  const origWriteText = Clipboard.prototype.writeText;
  const origWrite = Clipboard.prototype.write;
  const origSetData = DataTransfer.prototype.setData;
  const origExecCommand = Document.prototype.execCommand;
  const origDispatch = EventTarget.prototype.dispatchEvent;
  const origAdd = EventTarget.prototype.addEventListener;
  const origRemove = EventTarget.prototype.removeEventListener;
  const getSelection = window.getSelection.bind(window);
  const stringify = JSON.stringify;
  const CE = CustomEvent;

  const host = () => location.hostname || location.protocol.replace(":", "");
  const noticeText = () => A.notice(host());

  function pageText() {
    try {
      const body = document.body || document.documentElement;
      return body ? String(body.innerText || body.textContent || "").slice(0, 20000) : "";
    } catch (_) {
      return "";
    }
  }

  function selectedText() {
    const el = document.activeElement;
    if (el && (el.tagName === "TEXTAREA" || el.tagName === "INPUT")) {
      try {
        if (typeof el.selectionStart === "number" && el.selectionEnd > el.selectionStart) {
          return el.value.slice(el.selectionStart, el.selectionEnd);
        }
      } catch (_) { /* input types without selection */ }
    }
    return String(getSelection() || "");
  }

  function report(result, text, source) {
    const detail = stringify({
      verdict: result.verdict,
      score: result.score,
      reasons: result.reasons.slice(0, 12),
      decoded: result.decoded.slice(0, 3).map((d) => d.slice(0, MAX_REPORT)),
      text: text.slice(0, MAX_REPORT),
      source,
      host: host(),
      url: location.href.slice(0, 500),
      frame: window !== window.top,
    });
    try { origDispatch.call(document, new CE(EVENT, { detail })); } catch (_) { /* detached doc */ }
  }

  // Returns the analysis; reports anything that is not "allow".
  function inspect(text, source, programmatic) {
    const s = String(text == null ? "" : text);
    if (!s.trim() || s === noticeText()) return { verdict: "allow" };
    let result;
    try {
      result = A.analyze(s, { programmatic, pageText: pageText() });
    } catch (_) {
      return { verdict: "allow" };
    }
    if (result.verdict !== "allow") report(result, s, source);
    return result;
  }

  function disguise(wrapper, original) {
    // Keep name/length and a native-looking toString so pages that sniff
    // for tampering behave as they would without the extension.
    try {
      Object.defineProperty(wrapper, "name", { value: original.name });
      Object.defineProperty(wrapper, "length", { value: original.length });
      const native = Function.prototype.toString.call(original);
      Object.defineProperty(wrapper, "toString", { value: () => native });
    } catch (_) { /* best effort */ }
    return wrapper;
  }

  // --- navigator.clipboard.writeText ------------------------------------------
  Clipboard.prototype.writeText = disguise(function writeText(data) {
    const r = inspect(data, "clipboard.writeText", true);
    if (r.verdict === "block") return origWriteText.call(this, noticeText());
    return origWriteText.apply(this, arguments);
  }, origWriteText);

  // --- navigator.clipboard.write (ClipboardItem with text/plain) --------------
  if (origWrite) {
    Clipboard.prototype.write = disguise(function write(items) {
      const self = this;
      const args = arguments;
      const list = Array.from(items || []);
      const texts = list
        .filter((it) => it && Array.isArray(it.types) && it.types.includes("text/plain"))
        .map((it) => Promise.resolve(it.getType("text/plain")).then((b) => b.text()).catch(() => ""));
      if (!texts.length) return origWrite.apply(self, args);
      return Promise.all(texts).then((values) => {
        const blocked = values.some((v) => inspect(v, "clipboard.write", true).verdict === "block");
        return blocked ? origWriteText.call(self, noticeText()) : origWrite.apply(self, args);
      });
    }, origWrite);
  }

  // --- DataTransfer.setData (copy-event hijack) -------------------------------
  DataTransfer.prototype.setData = disguise(function setData(format, data) {
    const f = String(format).toLowerCase();
    if (f === "text" || f === "text/plain" || f === "text/html") {
      const text = f === "text/html" ? String(data).replace(/<[^>]*>/g, " ") : data;
      if (inspect(text, "copy-event setData", true).verdict === "block") {
        return origSetData.call(this, format, f === "text/html" ? "" : noticeText());
      }
    }
    return origSetData.apply(this, arguments);
  }, origSetData);

  // --- document.execCommand('copy') -------------------------------------------
  let execDepth = 0;
  Document.prototype.execCommand = disguise(function execCommand(command) {
    const cmd = String(command).toLowerCase();
    if (cmd !== "copy" && cmd !== "cut") return origExecCommand.apply(this, arguments);
    const r = inspect(selectedText(), "execCommand('" + cmd + "')", true);
    if (r.verdict !== "block") {
      execDepth++;
      try { return origExecCommand.apply(this, arguments); } finally { execDepth--; }
    }
    // Let the copy happen, but replace its payload before any page handler runs.
    const override = (e) => {
      origSetData.call(e.clipboardData, "text/plain", noticeText());
      e.preventDefault();
      e.stopImmediatePropagation();
    };
    origAdd.call(window, "copy", override, true);
    execDepth++;
    try {
      return origExecCommand.apply(this, arguments);
    } finally {
      execDepth--;
      origRemove.call(window, "copy", override, true);
    }
  }, origExecCommand);

  // --- User copies (Ctrl+C / context menu) of disguised selections ------------
  origAdd.call(window, "copy", (e) => {
    if (execDepth || !e.clipboardData) return;
    const r = inspect(selectedText(), "selection copy", false);
    if (r.verdict === "block") {
      origSetData.call(e.clipboardData, "text/plain", noticeText());
      e.preventDefault();
    }
  }, true);
})();
