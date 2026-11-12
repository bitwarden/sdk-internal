---
paths:
  - "e2e/**"
---

# E2E tests

Each folder under `e2e/` tests the SDK through one of its bindings: `e2e/wasm` through the WASM
package, and the other folders through the UniFFI bindings for one mobile language. They test the
same SDK, so a new test goes into every suite.

- A PR that adds a test to one binding's suite adds the matching test to every other suite in the
  same PR. Give the matching tests the same name, in each language's naming style, so the
  counterpart is easy to find.
- A PR that changes a test also changes its counterparts in the other suites, where they exist. The
  suites are not at parity: `e2e/wasm` has many tests the other suites never had, and a missing
  counterpart of an existing test is backlog, not part of the PR.
- If a new test cannot be written for a binding, say so in a comment next to the test and in the PR
  description. Two reasons qualify: the method is only exported to one binding, or the test needs
  harness pieces the other suite lacks, such as the server and client emulators in `e2e/wasm`.
  Building the missing harness is separate work, not part of the PR.
- When reviewing a change under `e2e/`, check the other suites for the counterpart of each added
  test and flag a missing one. For a changed test, check only the counterparts that exist.

Each suite's README says how to run it; the root `package.json` has an `e2e:<binding>` script for
each.
