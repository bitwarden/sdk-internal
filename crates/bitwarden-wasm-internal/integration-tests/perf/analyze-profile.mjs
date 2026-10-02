// Summarizes a V8 `.cpuprofile`, restricted to samples under a root frame (default: decrypt_list).
//
// Usage: node perf/analyze-profile.mjs <file.cpuprofile> [rootPattern] [topN]
//
// Prints self time and inclusive time per function, as a share of the root's total.

import { readFileSync } from "node:fs";

const [file, rootPattern = "decrypt_list", topArg = "40"] = process.argv.slice(2);
const TOP = Number(topArg);

const profile = JSON.parse(readFileSync(file, "utf8"));
const nodes = new Map(profile.nodes.map((n) => [n.id, n]));
const parent = new Map();
for (const n of profile.nodes) {
  for (const c of n.children ?? []) {
    parent.set(c, n.id);
  }
}

const name = (n) =>
  n.callFrame.functionName || `(anon ${n.callFrame.url}:${n.callFrame.lineNumber})`;
const self = new Map();
const inclusive = new Map();
let total = 0;

// Each sample ≈ one interval; weight by time delta for accuracy.
for (let i = 0; i < profile.samples.length; i++) {
  const dt = profile.timeDeltas[i] ?? 0;
  const stack = [];
  for (let id = profile.samples[i]; id !== undefined; id = parent.get(id)) {
    stack.push(nodes.get(id));
  }
  if (!stack.some((n) => name(n).includes(rootPattern))) {
    continue;
  }

  total += dt;
  const leaf = name(stack[0]);
  self.set(leaf, (self.get(leaf) ?? 0) + dt);
  for (const fn of new Set(stack.map(name))) {
    inclusive.set(fn, (inclusive.get(fn) ?? 0) + dt);
  }
}

const print = (title, map) => {
  console.log(`\n== ${title} (root total ${(total / 1000).toFixed(0)} ms) ==`);
  [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .slice(0, TOP)
    .forEach(([fn, t]) => {
      const pct = ((100 * t) / total).toFixed(1).padStart(5);
      console.log(`${pct}%  ${(t / 1000).toFixed(0).padStart(6)} ms  ${fn.slice(0, 150)}`);
    });
};

print("self", self);
print("inclusive", inclusive);
