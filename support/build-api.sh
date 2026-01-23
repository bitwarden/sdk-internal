#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../

mkdir -p ./artifacts
cp ../server/api.json ./artifacts/api.json
cp ../server/identity.json ./artifacts/identity.json

./support/generate-api-bindings-ci.sh
./support/generate-identity-bindings-ci.sh

rustup toolchain install nightly
cargo +nightly fmt
