// The case lives in a `#[cfg(any())]` module so it is parsed by the
// pre-expansion lint pass but never compiled. This lets us reference
// `uniffi::setup_scaffolding!` without pulling `uniffi` in as a
// dev-dependency.
//
// Should warn: this lint crate has a `Cargo.toml` but no `uniffi.toml`, which
// is the situation the lint reports. The passing case (a crate that does ship
// a `uniffi.toml`) can't be expressed here, since the crate under test is this
// one.
#[cfg(any())]
mod scaffolding_without_config {
    uniffi::setup_scaffolding!();
}

fn main() {}
