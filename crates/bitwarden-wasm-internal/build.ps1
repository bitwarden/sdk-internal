# Move to the root of the repository
Set-Location -Path (Join-Path (Get-Location) "..\..")

# Write VERSION file
git rev-parse HEAD | Out-File -FilePath ./crates/bitwarden-wasm-internal/npm/VERSION -Force

if ($args[0] -ne "-r") {
    Write-Host "Building in debug mode"
    $RELEASE_FLAG = ""
    $BUILD_FOLDER = "debug"
} else {
    Write-Host "Building in release mode"
    $RELEASE_FLAG = "--release"
    $BUILD_FOLDER = "release"
}

# Build with MVP CPU target
$env:RUSTFLAGS = "-Ctarget-cpu=mvp"
$env:RUSTC_BOOTSTRAP = "1"
cargo build -p bitwarden-wasm-internal -Zbuild-std="panic_abort,std" --target wasm32-unknown-unknown $RELEASE_FLAG

# Run wasm-bindgen
wasm-bindgen --target bundler --out-dir crates/bitwarden-wasm-internal/npm ./target/wasm32-unknown-unknown/$BUILD_FOLDER/bitwarden_wasm_internal.wasm
wasm-bindgen --target nodejs --out-dir crates/bitwarden-wasm-internal/npm/node ./target/wasm32-unknown-unknown/$BUILD_FOLDER/bitwarden_wasm_internal.wasm

# Format
npx prettier --write ./crates/bitwarden-wasm-internal/npm

# Optimize size
wasm-opt -Os ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm
wasm-opt -Os ./crates/bitwarden-wasm-internal/npm/node/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/npm/node/bitwarden_wasm_internal_bg.wasm

# Transpile to JS
wasm2js ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js
npx terser ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js -o ./crates/bitwarden-wasm-internal/npm/bitwarden_wasm_internal_bg.wasm.js
