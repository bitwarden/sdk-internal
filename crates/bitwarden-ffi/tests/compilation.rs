#![allow(missing_docs)]

#[test]
fn compilation_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compilation_tests/*.rs");
    // These fail only because of what the macros generate under the `wasm` feature; without it,
    // the macros add nothing and the cases compile.
    #[cfg(feature = "wasm")]
    t.compile_fail("tests/compilation_tests/wasm/*.rs");
}
