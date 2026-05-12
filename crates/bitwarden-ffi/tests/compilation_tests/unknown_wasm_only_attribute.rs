use bitwarden_ffi::wasm_export;

struct Foo;

#[wasm_export]
impl Foo {
    #[wasm_only(message = "hello")]
    pub fn bar() {}
}

fn main() {}
