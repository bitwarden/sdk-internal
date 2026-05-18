#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"
cd ../

mkdir -p ./artifacts

SDK_ROOT="$(pwd)"
SERVER_DIR="../server"

# Extract expected commit hashes from READMEs
API_COMMIT=$(grep -A1 'Server Git commit' crates/bitwarden-api-api/README.md | grep -oE '[a-f0-9]{40}' | head -1)
IDENTITY_COMMIT=$(grep -A1 'Server Git commit' crates/bitwarden-api-identity/README.md | grep -oE '[a-f0-9]{40}' | head -1)
echo "Expected commits: API=$API_COMMIT, Identity=$IDENTITY_COMMIT"

# Check if existing artifacts are already up to date
CURRENT_API_COMMIT=$(jq -r '.["x-git-commit"] // empty' "$SDK_ROOT/artifacts/api.json" 2>/dev/null)
CURRENT_IDENTITY_COMMIT=$(jq -r '.["x-git-commit"] // empty' "$SDK_ROOT/artifacts/identity.json" 2>/dev/null)

if [ "$CURRENT_API_COMMIT" = "$API_COMMIT" ] && [ "$CURRENT_IDENTITY_COMMIT" = "$IDENTITY_COMMIT" ]; then
    echo "Artifacts are already up to date, skipping server checkout and generation."
else
    cd "$SERVER_DIR"
    if [ -n "$(git status --porcelain)" ]; then
        echo "Error: Server repository has uncommitted changes. Please commit or stash them first."
        exit 1
    fi
    git fetch origin

    # Generate API JSON
    if [ "$CURRENT_API_COMMIT" != "$API_COMMIT" ]; then
        git checkout "$API_COMMIT"
        pwsh ./dev/generate_openapi_files.ps1
        cp api.json "$SDK_ROOT/artifacts/api.json"
    fi

    # Generate Identity JSON
    if [ "$CURRENT_IDENTITY_COMMIT" != "$IDENTITY_COMMIT" ]; then
        git checkout "$IDENTITY_COMMIT"
        pwsh ./dev/generate_openapi_files.ps1
        cp identity.json "$SDK_ROOT/artifacts/identity.json"
    fi
fi

cd "$SDK_ROOT"
./support/generate-api-bindings-ci.sh
./support/generate-identity-bindings-ci.sh

if ! cargo +nightly fmt --version &>/dev/null; then
    rustup toolchain install nightly
fi
cargo +nightly fmt
