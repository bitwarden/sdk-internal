---
paths:
  - "crates/bitwarden-api-api/**"
  - "crates/bitwarden-api-identity/**"
---

# Generated API crates

These crates are generated from the Bitwarden server's OpenAPI specs. Do not edit them by hand —
regeneration overwrites everything.

- Regenerate locally with `./support/build-api.sh` (expects a sibling `server` checkout), or via the
  "Update API Bindings" GitHub workflow.
- To change the generated output, edit the templates in `support/openapi-template/` or fix the
  server-side spec, then regenerate.
