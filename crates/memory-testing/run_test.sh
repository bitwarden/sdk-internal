#!/usr/bin/env bash
set -eo pipefail

cd "$(dirname "$0")"

# Move to the root of the repository
cd ../../

BASE_DIR="./crates/memory-testing"

mkdir -p $BASE_DIR/output
rm $BASE_DIR/output/* || true

cargo build -p memory-testing --release

if [ "$1" = "no-docker" ]; then
    # This specifically needs to run as root to be able to capture core dumps
    sudo ./target/release/capture-dumps ./target/release/memory-testing $BASE_DIR
else
    docker build -f crates/memory-testing/Dockerfile -t bitwarden/memory-testing .
    docker run --rm -it --privileged --cap-add=SYS_PTRACE -v $BASE_DIR/output:/output bitwarden/memory-testing 
fi

./target/release/analyze-dumps $BASE_DIR
