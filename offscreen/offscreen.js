// Chrome offscreen document: the only extension context in MV3 Chrome that can
// write the clipboard without a focused tab (see background.js writeClipboard).
"use strict";

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "offscreen-copy") return;
  const ta = document.createElement("textarea");
  ta.value = String(msg.text);
  document.body.append(ta);
  ta.select();
  const ok = document.execCommand("copy");
  ta.remove();
  sendResponse(ok);
});
