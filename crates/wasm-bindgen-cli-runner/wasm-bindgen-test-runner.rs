//! Wrapper binary for `wasm-bindgen` CLI to ensure version consistency and avoid manual
//! installation.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    wasm_bindgen_cli::wasm_bindgen_test_runner::run_cli_with_args(std::env::args_os())?;
    Ok(())
}
