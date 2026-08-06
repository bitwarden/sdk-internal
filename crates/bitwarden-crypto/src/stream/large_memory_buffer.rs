//! A module for allocating large remote buffers not in WASM memory. WASM generally does not support
//! resizing the heap after it has been allocated, so we need to allocate a buffer that can be
//! released again.
//!
//! The buffer is allocated once to an exact size at construction and is never resized, since
//! resizing a `Uint8Array` on WASM is slow (it requires allocating a new array and copying).
//!
//! This is used for streaming encryption in the legacy format.

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

    // Total allocated capacity in bytes. Fixed at construction; the buffer never grows.
    capacity: usize,

    // Write cursor: the number of bytes appended so far.
    position: usize,
}

#[derive(Debug)]
pub(crate) struct InvalidIndexError;

impl Buffer {
    pub fn new(capacity: usize) -> Self {
        Self {
            #[cfg(target_arch = "wasm32")]
            inner: js_sys::Uint8Array::new_with_length(capacity as u32).into(),

            #[cfg(not(target_arch = "wasm32"))]
            inner: vec![0; capacity],

            capacity,
            position: 0,
        }
    }

    pub fn index(&self, index: std::ops::Range<usize>) -> Result<Vec<u8>, InvalidIndexError> {
        if index.end > self.capacity || index.start > index.end {
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
        if self.position + data.len() > self.capacity {
            return Err(InvalidIndexError);
        }

        #[cfg(target_arch = "wasm32")]
        {
            self.inner
                .subarray(self.position as u32, (self.position + data.len()) as u32)
                .copy_from(data);
        }

        #[cfg(not(target_arch = "wasm32"))]
        {
            self.inner[self.position..self.position + data.len()].copy_from_slice(data);
        }

        self.position += data.len();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_buffer() {
        let mut buffer = Buffer::new(5);
        buffer
            .append(&[1, 2, 3, 4, 5])
            .expect("range must be valid");
        assert_eq!(&buffer.index(0..5).unwrap(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_append_advances_write_cursor() {
        let mut buffer = Buffer::new(9);
        buffer
            .append(&[1, 2, 3, 4, 5])
            .expect("range must be valid");
        buffer.append(&[6, 7, 8, 9]).expect("range must be valid");
        assert_eq!(&buffer.index(0..9).unwrap(), &[1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn test_append_past_capacity_errors() {
        let mut buffer = Buffer::new(4);
        assert!(buffer.append(&[1, 2, 3, 4, 5]).is_err());
    }
}
