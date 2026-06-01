//! A module for allocating large remote buffers not in WASM memory. WASM generally does not support
//! resizing the heap after it has been allocated, so we need to allocate a buffer that can be
//! released again.
//!
//! Allocations are made exponentially to minimize over-allocation while keeping re-allocations low.
//!
//! This is used for streaming encryption in the legacy format.

/// Buffers are allocated and grown in multiples of this value.
const INITIAL_SIZE: usize = 8 * 1024 * 1024;

// Gives the size as a multiple of blocks that fits the requested size.
fn next_size(current: usize, required: usize) -> usize {
    current.saturating_mul(2).max(required).max(INITIAL_SIZE)
}

pub struct Buffer {
    // The Uint8Array lives in JS memory, and wasm merely keeps a reference to it in the
    // wasm-bindgen-glue-code-heap `https://wasm-bindgen.github.io/wasm-bindgen/contributing/design/js-objects-in-rust.html#long-lived-js-objects`
    // We cannot convert the full arary to slice / Vec because that would require allocating and
    // copying the data to WASM memory. Instead, we create slice access operations.
    //
    // It is freed automatically by the host JS engine's garbage collector, as soon as the rust
    // side drops the reference. The wasm-bindgen-glue-code-heap releases the JS-side reference
    // as soon as the rust side reference is
    //
    // Please note, while chrome / firefox do release the memory from the JS environment, on the OS
    // side they may keep the memory allocated for a while regardless.
    #[cfg(target_arch = "wasm32")]
    inner: js_sys::Uint8Array,

    // On non-wasm targets, deallocating memory is supported so we can just use a Vec<u8> that
    // lives on the heap and is managed by regular Rust ownership rules.
    #[cfg(not(target_arch = "wasm32"))]
    inner: Vec<u8>,

    size: usize,
}

#[derive(Debug)]
pub(crate) struct InvalidIndexError;

impl Buffer {
    pub fn new() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            inner: js_sys::Uint8Array::new_with_length(INITIAL_SIZE as u32).into(),

            #[cfg(not(target_arch = "wasm32"))]
            inner: vec![0; INITIAL_SIZE],

            size: INITIAL_SIZE,
        }
    }

    pub fn index(&self, index: std::ops::Range<usize>) -> Result<Vec<u8>, InvalidIndexError> {
        if index.end > self.size || index.start > index.end {
            return Err(InvalidIndexError);
        }

        #[cfg(target_arch = "wasm32")]
        {
            Ok(self
                .inner
                .slice(index.start as u32, index.end as u32)
                .to_vec())
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            Ok(self.inner[index].to_vec())
        }
    }

    pub fn append(&mut self, data: &[u8]) -> Result<(), InvalidIndexError> {
        if self.size + data.len() > self.size {
            self.grow_to_fit(self.size + data.len());
        }

        #[cfg(target_arch = "wasm32")]
        {
            self.inner
                .subarray(self.size as u32, (self.size + data.len()) as u32)
                .copy_from(data);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner[self.size..self.size + data.len()].copy_from_slice(data);
        }

        Ok(())
    }

    fn grow_to_fit(&mut self, required: usize) {
        let new_size = next_size(self.size, required);

        #[cfg(target_arch = "wasm32")]
        {
            let new_array = js_sys::Uint8Array::new_with_length(new_size as u32);
            let old_array = &self.inner;
            new_array.set(&old_array, 0);
            self.inner = new_array;
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner.resize(new_size, 0);
        }

        self.size = new_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer() {
        let mut buffer = Buffer::new();
        buffer
            .append(&[1, 2, 3, 4, 5])
            .expect("range must be valid");
        assert_eq!(&buffer.index(0..5).unwrap(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_write_past_capacity_grows() {
        let mut buffer = Buffer::new();
        buffer
            .append(&[1, 2, 3, 4, 5])
            .expect("range must be valid");

        let position = INITIAL_SIZE;
        buffer.append(&[6, 7, 8, 9]).expect("range must be valid");

        assert_eq!(buffer.size, 2 * INITIAL_SIZE);
        assert_eq!(&buffer.index(0..5).unwrap(), &[1, 2, 3, 4, 5]);
        assert_eq!(
            &buffer.index(position..position + 4).unwrap(),
            &[6, 7, 8, 9]
        );
    }
}
