fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let args: Vec<_> = std::env::args().skip(1).collect();

    let [target, out_dir, input] = args
        .try_into()
        .expect("Usage: cargo run -p wasm-bindgen-cli-runner -- <TARGET> <OUT_DIR> <INPUT>");

    let mut b = wasm_bindgen_cli_support::Bindgen::new();
    match target.as_str() {
        "bundler" => b.bundler(true)?,
        "nodejs" => b.nodejs(true)?,
        s => panic!("invalid target: `{s}`"),
    };

    b.typescript(true)
        .input_path(input)
        .generate(out_dir)
        .map_err(Into::into)
}
