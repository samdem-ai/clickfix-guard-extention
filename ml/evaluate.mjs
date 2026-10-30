// Leave-one-family-out evaluation. For each malicious family F, the model is
// trained without F and tested on F (attack style it never saw) plus held-out
// benign samples. Compares rules alone, the model alone, and the fused analyzer.
//
// Worst case on purpose: no page context, no intent signals (visibility,
// button label), just the copied text with "written by script". Real
// detections also get those signals.
//
// Run: node ml/evaluate.mjs        (writes ml/results.json)
import { writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { generate, rng } from "./corpus.mjs";
import { A, train, vectorize } from "./lr.mjs";

const HERE = dirname(fileURLToPath(import.meta.url));
// A different seed from the shipped model's corpus, so no sample is shared.
const { malicious, benign } = generate({ seed: 2026 });
const r = rng(99);
const shuffled = benign.map((b) => [r(), b]).sort((x, y) => x[0] - y[0]).map((x) => x[1]);
const cut = Math.floor(shuffled.length * 0.8);
const benignTrain = shuffled.slice(0, cut);
const benignTest = shuffled.slice(cut);
const families = [...new Set(malicious.map((m) => m.family))];

const ctx = (model) => ({ programmatic: true, model });
const rate = (xs, f) => xs.filter(f).length / xs.length;
const pct = (x) => `${(100 * x).toFixed(1)}%`;

const rows = [];
let fprAcc = { rules: 0, ml: 0, fused: 0, fusedWarn: 0 };
for (const fam of families) {
  const trainSet = [...malicious.filter((m) => m.family !== fam), ...benignTrain];
  const model = train(vectorize(trainSet));
  const test = malicious.filter((m) => m.family === fam);
  const det = {
    rules: rate(test, (s) => A.analyze(s.text, ctx(null)).verdict === "block"),
    ml: rate(test, (s) => A.predict(model, A.corpusOf(s.text).corpus) >= 0.5),
    fused: rate(test, (s) => A.analyze(s.text, ctx(model)).verdict === "block"),
    fusedFlag: rate(test, (s) => A.analyze(s.text, ctx(model)).verdict !== "allow"),
  };
  const fp = {
    rules: rate(benignTest, (s) => A.analyze(s.text, ctx(null)).verdict === "block"),
    ml: rate(benignTest, (s) => A.predict(model, A.corpusOf(s.text).corpus) >= 0.5),
    fused: rate(benignTest, (s) => A.analyze(s.text, ctx(model)).verdict === "block"),
    fusedWarn: rate(benignTest, (s) => A.analyze(s.text, ctx(model)).verdict === "warn"),
  };
  for (const k of Object.keys(fprAcc)) fprAcc[k] += fp[k] / families.length;
  rows.push({ family: fam, n: test.length, ...det, fp });
}

const mean = (k) => rows.reduce((a, x) => a + x[k], 0) / rows.length;
console.log("held-out family            n   rules   model   fused(block)  fused(block|warn)");
for (const x of rows) {
  console.log(`${x.family.padEnd(24)} ${String(x.n).padStart(4)}  ${pct(x.rules).padStart(6)}  ${pct(x.ml).padStart(6)}  ${pct(x.fused).padStart(11)}  ${pct(x.fusedFlag).padStart(16)}`);
}
console.log(`${"mean".padEnd(24)}       ${pct(mean("rules")).padStart(6)}  ${pct(mean("ml")).padStart(6)}  ${pct(mean("fused")).padStart(11)}  ${pct(mean("fusedFlag")).padStart(16)}`);
console.log(`\nbenign held-out (n=${benignTest.length}) false-positive rate:  rules ${pct(fprAcc.rules)}  model ${pct(fprAcc.ml)}  fused block ${pct(fprAcc.fused)}  (fused warn ${pct(fprAcc.fusedWarn)})`);

writeFileSync(join(HERE, "results.json"), JSON.stringify({
  setup: "leave-one-family-out, no page context, programmatic copy; corpus seed 2026",
  families: rows,
  mean: { rules: mean("rules"), ml: mean("ml"), fused: mean("fused"), fusedFlag: mean("fusedFlag") },
  benignFalsePositive: fprAcc,
  benignTestSize: benignTest.length,
}, null, 2) + "\n");
