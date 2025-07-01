#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../

# Delete old directory to ensure all files are updated
rm -rf crates/bitwarden-api-api/src

VERSION=$(grep '^version = ".*"' Cargo.toml | cut -d '"' -f 2)

# Generate new API bindings
npx openapi-generator-cli generate \
    -i ../server/api.json \
    -g rust \
    -o crates/bitwarden-api-api \
    --package-name bitwarden-api-api \
    -t ./support/openapi-template \
    --additional-properties=library=reqwest-trait,mockall,topLevelApiClient,packageVersion=$VERSION,packageDescription=\"Api bindings for the Bitwarden API.\"

# Delete old directory to ensure all files are updated
rm -rf crates/bitwarden-api-identity/src

# Generate new Identity bindings
npx openapi-generator-cli generate \
    -i ../server/identity.json \
    -g rust \
    -o crates/bitwarden-api-identity \
    --package-name bitwarden-api-identity \
    -t ./support/openapi-template \
    --additional-properties=library=reqwest-trait,mockall,topLevelApiClient,packageVersion=$VERSION,packageDescription=\"Api bindings for the Bitwarden Identity API.\"

rustup toolchain install nightly

# Rustfmt has what looks like a bug, where it requires multiple passes to format the code.
# For example with code like this:
# ```rust
# /// Test Doc
# ///
# ///
# fn test() {}
# ```
# The first pass will remove one of the empty lines but not the second one, so we need a
# second pass to remove the second empty line. The swagger generated code adds three comment
# lines, for path, description and notes and for us the last two are usually empty, which explains
# the need for these two passes.
cargo +nightly fmt
cargo +nightly fmt

npm run prettier
