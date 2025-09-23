use std::{
    alloc::{GlobalAlloc, Layout},
    ptr::NonNull,
};

use allocator_api2::alloc::{AllocError, Allocator};

pub(crate) struct MlockAlloc(crate::ZeroizingAllocator<std::alloc::System>);

impl MlockAlloc {
    pub fn new() -> Self {
        Self(crate::ZeroizingAllocator(std::alloc::System))
    }
}

unsafe impl Allocator for MlockAlloc {
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

        let ptr = unsafe { self.0.alloc(layout) };

        if ptr.is_null() {
            return Err(AllocError);
        }
        unsafe { memsec::mlock(ptr, layout.size()) };
        Ok(unsafe {
            let slice = std::slice::from_raw_parts_mut(ptr, layout.size());
            NonNull::new(slice).expect("slice is never null")
        })
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        if layout.size() == 0 {
            return;
        }

        memsec::munlock(ptr.as_ptr(), layout.size());
        self.0.dealloc(ptr.as_ptr(), layout);
    }
}
