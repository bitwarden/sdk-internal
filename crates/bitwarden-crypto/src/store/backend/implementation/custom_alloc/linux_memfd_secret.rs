use std::{alloc::Layout, ptr::NonNull, sync::OnceLock};

use allocator_api2::alloc::{AllocError, Allocator};

pub(crate) struct LinuxMemfdSecretAlloc;

impl LinuxMemfdSecretAlloc {
    pub fn new() -> Option<Self> {
        fn is_available() -> bool {
            static IS_SUPPORTED: OnceLock<bool> = OnceLock::new();

            *IS_SUPPORTED.get_or_init(|| unsafe {
                let Some(ptr) = (unsafe { memsec::memfd_secret_sized(1) }) else {
                    return false;
                };
                memsec::free_memfd_secret(ptr);
                true
            })
        }

        if !is_available() {
            return None;
        }

        Some(Self)
    }
}

unsafe impl Allocator for LinuxMemfdSecretAlloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Note: The allocator_api2 Allocator traits requires us to handle zero-sized allocations.
        // We return an invalid pointer as you cannot allocate a zero-sized slice in most
        // allocators. This is what allocator_api2::Global does as well:
        // https://github.com/zakarumych/allocator-api2/blob/2dde97af85f3559619689cef152e90e6d8a0cee3/src/alloc/global.rs#L24-L29
        if layout.size() == 0 {
            return Ok(unsafe {
                NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(
                    layout.align() as *mut u8,
                    0,
                ))
            });
        }

        let ptr: NonNull<[u8]> = unsafe { memsec::memfd_secret_sized(layout.size()) }
            .expect("memfd_secret_sized failed");

        Ok(ptr)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if layout.size() == 0 {
            return;
        }

        memsec::free_memfd_secret(ptr);
    }
}
