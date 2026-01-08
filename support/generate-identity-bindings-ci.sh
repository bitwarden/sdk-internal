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
    -i artifacts/identity.json \
    -g rust \
    -o crates/bitwarden-api-identity \
    --package-name bitwarden-api-identity \
    -t ./support/openapi-template \
    --additional-properties=library=reqwest-trait,mockall,topLevelApiClient,packageVersion=$VERSION,packageDescription=\"API bindings for Bitwarden Identity.\"
    
npm run prettier
