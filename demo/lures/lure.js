// Tells the demo page which (inert) payload this simulated lure tried to copy,
// so it can show the visitor what landed on their clipboard.
window.reportCopy = function (scenario, payload) {
  parent.postMessage({ type: "cfg-demo-copied", scenario, payload }, location.origin);
};
