fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    wasm_bindgen_cli::wasm_bindgen::run_cli_with_args(std::env::args_os())?;
    Ok(())
}
