use bitwarden_ffi::wasm_export;

pub struct BwStream<T>(T);

pub struct Canvas;

#[wasm_export]
impl Canvas {
    pub fn points(&self) -> BwStream<(u32, u32)> {
        BwStream((0, 0))
    }
}

fn main() {}
