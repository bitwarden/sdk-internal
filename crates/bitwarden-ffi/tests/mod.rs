#![allow(missing_docs)]

mod wasm_export;

#[test]
fn compilation_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compilation_tests/*.rs");
}
