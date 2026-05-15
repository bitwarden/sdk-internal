#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../

VERSION=$(grep '^version = ".*"' Cargo.toml | cut -d '"' -f 2)

# Delete old directory to ensure all files are updated
rm -rf crates/bitwarden-api-api/src

# Generate new API bindings
npx openapi-generator-cli generate \
    -c ./support/openapi-config.yaml \
    -i artifacts/api.json \
    -o crates/bitwarden-api-api \
    --package-name bitwarden-api-api \
    --additional-properties=packageVersion=$VERSION,packageDescription=\"API bindings for the Bitwarden API.\"

npm run prettier
