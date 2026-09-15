#!/usr/bin/env node
/**
 * Post-process uniffi-generated Kotlin bindings to wrap every
 * `uniffiRustCallAsync(...)` call in `withContext(Dispatchers.IO)`.
 *
 * Workaround for mozilla/uniffi-rs#1901: under Dispatchers.Unconfined, the
 * caller's continuation resumes inline on the thread that fires the foreign
 * callback's wake, while uniffi's RustFuture scheduler still holds its
 * internal Mutex. The resumed body re-enters Rust via pollFunc and
 * deadlocks trying to re-acquire that Mutex on the same thread.
 *
 * Wrapping every Kotlin->Rust async entry point in withContext(Dispatchers.IO)
 * forces the captured Continuation onto the IO dispatcher regardless of the
 * caller's context, so resume() posts to a worker queue instead of running
 * inline. The lock is released before pollFunc runs again. No deadlock.
 *
 * Run after `uniffi-bindgen generate`. Exits non-zero if no matches are
 * found across all .kt files under the supplied root, on the assumption
 * that the build pipeline always sees fresh, unwrapped output and a zero
 * total means the uniffi template has shifted and this script needs
 * updating.
 */

"use strict";

const fs = require("fs");
const path = require("path");

// Match: "        return uniffiRustCallAsync(" through its matching "\n    )\n    }"
// and rewrite to wrap in withContext(Dispatchers.IO).
const PATTERN =
  /(        return )uniffiRustCallAsync\((\n(?:.*\n)*?    \))(\n    \})/g;

function wrap(content) {
  let count = 0;
  const out = content.replace(PATTERN, (_match, head, body, tail) => {
    count += 1;
    return (
      `${head}kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {\n` +
      `            uniffiRustCallAsync(${body}\n` +
      `        }${tail}`
    );
  });
  return { out, count };
}

// Counted independently of the wrap regex so a uniffi template change that
// keeps `override suspend fun` but moves the `uniffiRustCallAsync` call (or
// renames it) is detected as a mismatch.
function countSuspendFns(content) {
  return (content.match(/override suspend fun/g) || []).length;
}

function* walkKotlin(root) {
  for (const entry of fs.readdirSync(root, { withFileTypes: true })) {
    const p = path.join(root, entry.name);
    if (entry.isDirectory()) yield* walkKotlin(p);
    else if (entry.isFile() && p.endsWith(".kt")) yield p;
  }
}

function main(roots) {
  if (roots.length === 0) {
    console.error("usage: wrap-async-bindings.js <dir> [dir ...]");
    process.exit(2);
  }

  let totalWrapped = 0;
  let totalDecls = 0;
  for (const file of walkKotlin(roots[0])) {
    const text = fs.readFileSync(file, "utf8");
    totalDecls += countSuspendFns(text);
    const { out, count } = wrap(text);
    if (count > 0) {
      fs.writeFileSync(file, out);
      console.log(`${file}: wrapped ${count} async fns`);
      totalWrapped += count;
    }
  }

  if (totalDecls === 0) {
    console.error(
      "wrap-async-bindings.js: no `override suspend fun` declarations found. " +
        "Check that the input directory contains uniffi-generated Kotlin bindings.",
    );
    process.exit(1);
  }
  if (totalWrapped !== totalDecls) {
    console.error(
      `wrap-async-bindings.js: wrapped ${totalWrapped} call sites but found ` +
        `${totalDecls} \`override suspend fun\` declarations. The uniffi-generated ` +
        "template may have changed; update the regex.",
    );
    process.exit(1);
  }
}

main(process.argv.slice(2));
