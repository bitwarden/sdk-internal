#!/usr/bin/env bash
set -eo pipefail

# Build script to regenerate Keeper protobuf Rust code from .proto definitions.
# Run this after modifying any .proto files in crates/bitwarden-importers/proto/keeper/

cd "$(dirname "$0")/.."

IMPORTER_CRATE="crates/bitwarden-importers"
PROTO_DIR="$IMPORTER_CRATE/proto/keeper"
OUT_DIR="$IMPORTER_CRATE/src/importers/keeper/proto"

if [ ! -d "$PROTO_DIR" ]; then
    echo "Error: Proto directory not found: $PROTO_DIR"
    exit 1
fi

if ! command -v "${PROTOC:-protoc}" > /dev/null 2>&1; then
    echo "Error: protoc not found. prost-build requires the Protocol Buffers compiler on PATH (or set PROTOC)."
    exit 1
fi

echo "Regenerating Keeper protobuf Rust code..."
echo "  Proto files: $PROTO_DIR"
echo "  Output dir:  $OUT_DIR"

# Create output directory if it doesn't exist
mkdir -p "$OUT_DIR"

# Use cargo-run-bin to invoke prost-build via a temporary Rust build script.
# Since we removed the permanent build.rs, we use a one-shot tool approach.
cargo run --quiet --manifest-path support/protobuf/Cargo.toml --bin build-keeper-proto -- "$PROTO_DIR" "$OUT_DIR"

# Format generated code to match rustfmt settings in rustfmt.toml
npm run lint:fix -- --only fmt > /dev/null

echo "✓ Keeper protobuf code regenerated successfully"
echo ""
echo "Review changes with: git diff $OUT_DIR"
echo "Commit with: git add $OUT_DIR && git commit -m 'chore: regenerate Keeper protobuf code'"
