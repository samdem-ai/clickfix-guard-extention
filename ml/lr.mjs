// Logistic regression over the analyzer's hashed n-gram features, trained with
// SGD. Pure JS so the shipped weights come from the exact browser feature code.
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
export const A = require("../src/analyzer.js");

export function vectorize(samples) {
  return samples.map((s) => ({ ...A.featurize(A.corpusOf(s.text).corpus), y: s.label }));
}

export function train(vectors, { epochs = 14, lr = 0.5, l2 = 1e-5, seed = 7 } = {}) {
  const w = new Float64Array(A.NGRAM_BUCKETS);
  let b = 0;
  const order = vectors.map((_, i) => i);
  let s = seed;
  const rand = () => ((s = (Math.imul(s, 1103515245) + 12345) >>> 0) / 4294967296);
  for (let e = 0; e < epochs; e++) {
    for (let i = order.length - 1; i > 0; i--) {
      const j = Math.floor(rand() * (i + 1));
      [order[i], order[j]] = [order[j], order[i]];
    }
    const step = lr / (1 + 0.3 * e);
    for (const k of order) {
      const { idx, val, y } = vectors[k];
      let z = b;
      for (let i = 0; i < idx.length; i++) z += w[idx[i]] * val[i];
      const g = 1 / (1 + Math.exp(-z)) - y;
      for (let i = 0; i < idx.length; i++) w[idx[i]] -= step * (g * val[i] + l2 * w[idx[i]]);
      b -= step * g;
    }
  }
  return { b, w: Array.from(w) };
}

export function quantize(model, digits = 3) {
  const f = 10 ** digits;
  return { b: Math.round(model.b * f) / f, w: model.w.map((x) => Math.round(x * f) / f) };
}
