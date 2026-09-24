#![allow(missing_docs)]

#[test]
fn compilation_tests() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compilation_tests/*.rs");
}
