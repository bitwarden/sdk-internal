//! A module for allocating large remote buffers not in WASM memory. WASM generally does not support
//! resizing the heap after it has been allocated, so we need to allocate a buffer that can be
//! released again.
//!
//! Allocations are made in 32 MiB blocks. Writes that exceed the current allocation grow the
//! buffer by additional 32 MiB blocks, preserving previously written data.
//!
//! This is used for streaming encryption in the legacy format.

/// Buffers are allocated and grown in multiples of this value.
const BLOCK_SIZE: usize = 32 * 1024 * 1024;
#[cfg(target_arch = "wasm32")]
const INITIAL_SIZE: usize = 1024 * 1024;

// Gives the size as a multiple of blocks that fits the requested size.
fn round_up_to_block(size: usize) -> usize {
    size.div_ceil(BLOCK_SIZE).max(1) * BLOCK_SIZE
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
pub(crate) struct OutOfBoundsError;

impl Buffer {
    pub fn new() -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            inner: js_sys::Uint8Array::new_with_length(INITIAL_SIZE as u32).into(),

            #[cfg(not(target_arch = "wasm32"))]
            inner: Vec::new(),

            size: 0,
        }
    }

    pub fn index(&self, index: std::ops::Range<usize>) -> Result<Vec<u8>, OutOfBoundsError> {
        if index.end > self.size {
            return Err(OutOfBoundsError);
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

    pub fn copy_from_slice(
        &mut self,
        index: std::ops::Range<usize>,
        data: &[u8],
    ) -> Result<(), OutOfBoundsError> {
        if index.end > self.size {
            self.grow_to_fit(index.end);
        }

        #[cfg(target_arch = "wasm32")]
        {
            let data_uint8_array = js_sys::Uint8Array::from(data);
            self.inner.set(&data_uint8_array, index.start as u32);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner[index].copy_from_slice(data);
        }

        Ok(())
    }

    fn grow_to_fit(&mut self, required: usize) {
        let new_size = round_up_to_block(required);

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
            .copy_from_slice(0..5, &[1, 2, 3, 4, 5])
            .expect("range must be valid");
        assert_eq!(&buffer.index(0..5).unwrap(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_initial_alloc_rounds_up_to_block_size() {
        let buffer = Buffer::new();
        assert_eq!(buffer.size, 0);
    }

    #[test]
    fn test_write_past_capacity_grows_in_blocks() {
        let mut buffer = Buffer::new();
        buffer
            .copy_from_slice(0..5, &[1, 2, 3, 4, 5])
            .expect("range must be valid");

        let position = BLOCK_SIZE;
        buffer
            .copy_from_slice(position..position + 4, &[6, 7, 8, 9])
            .expect("range must be valid");

        assert_eq!(buffer.size, 2 * BLOCK_SIZE);
        assert_eq!(&buffer.index(0..5).unwrap(), &[1, 2, 3, 4, 5]);
        assert_eq!(
            &buffer.index(position..position + 4).unwrap(),
            &[6, 7, 8, 9]
        );
    }

    #[test]
    fn test_grow_spanning_multiple_blocks() {
        let mut buffer = Buffer::new();
        let position = 3 * BLOCK_SIZE + 100;
        buffer
            .copy_from_slice(position..position + 3, &[1, 2, 3])
            .expect("range must be valid");
        assert_eq!(buffer.size, 4 * BLOCK_SIZE);
        assert_eq!(&buffer.index(position..position + 3).unwrap(), &[1, 2, 3]);
    }
}
