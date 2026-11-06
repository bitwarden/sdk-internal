---
paths:
  - "e2e/**"
---

# E2E tests

Each folder under `e2e/` tests the SDK through one of its bindings: `e2e/wasm` through the WASM
package, and the other folders through the UniFFI bindings for one mobile language. The suites cover
the same behavior, so they stay in sync.

- When a PR adds or changes a test in one binding's suite, it adds or changes the matching test in
  every other suite in the same PR. Give the matching tests the same name, in each language's naming
  style, so the counterpart is easy to find.
- If a test cannot exist for a binding, for example because the method is only exported to WASM, say
  so in a comment next to the test and in the PR description.
- When reviewing a change under `e2e/`, check every other suite for the counterpart of each added or
  changed test, and flag a missing one.

Each suite's README says how to run it; the root `package.json` has an `e2e:<binding>` script for
each.
