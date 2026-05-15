#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../

VERSION=$(grep '^version = ".*"' Cargo.toml | cut -d '"' -f 2)

# Delete old directory to ensure all files are updated
rm -rf crates/bitwarden-api-identity/src

# Generate new Identity bindings
npx openapi-generator-cli generate \
    -c ./support/openapi-config.yaml \
    -i artifacts/identity.json \
    -o crates/bitwarden-api-identity \
    --package-name bitwarden-api-identity \
    --additional-properties=packageVersion=$VERSION,packageDescription=\"API bindings for Bitwarden Identity.\"

npm run prettier
