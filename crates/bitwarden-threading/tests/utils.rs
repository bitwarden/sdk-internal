#[allow(unused)]
pub struct UnSend(*const ());
unsafe impl Sync for UnSend {}

#[allow(unused)]
pub struct UnSync(*const ());
unsafe impl Send for UnSync {}
