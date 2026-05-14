// Each case lives in its own `#[cfg(any())]` module so it is parsed by the
// pre-expansion lint pass but never compiled. This lets us reference
// `#[uniffi::export]` without pulling `uniffi` in as a dev-dependency.

// Should warn: missing async_runtime entirely.
#[cfg(any())]
mod missing_runtime_no_args {
    pub struct Foo;

    #[uniffi::export]
    impl Foo {
        pub async fn bar(&self) {}
    }
}

// Should warn: has other args but missing async_runtime.
#[cfg(any())]
mod missing_runtime_other_args {
    pub struct Foo;

    #[uniffi::export(callback_interface)]
    impl Foo {
        pub async fn bar(&self) {}
    }
}

// Should warn: async_runtime set to a non-tokio value.
#[cfg(any())]
mod wrong_runtime_value {
    pub struct Foo;

    #[uniffi::export(async_runtime = "other")]
    impl Foo {
        pub async fn bar(&self) {}
    }
}

// Should NOT warn: correct usage.
#[cfg(any())]
mod correct_usage {
    pub struct Foo;

    #[uniffi::export(async_runtime = "tokio")]
    impl Foo {
        pub async fn bar(&self) {}
    }
}

// Should NOT warn: impl with only sync fns does not require async_runtime.
#[cfg(any())]
mod sync_only_impl {
    pub struct Foo;

    #[uniffi::export]
    impl Foo {
        pub fn bar(&self) {}
    }
}

// Should warn: free async fn without async_runtime.
#[cfg(any())]
mod free_async_fn_missing_runtime {
    #[uniffi::export]
    pub async fn bar() {}
}

// Should NOT warn: free async fn with correct async_runtime.
#[cfg(any())]
mod free_async_fn_correct {
    #[uniffi::export(async_runtime = "tokio")]
    pub async fn bar() {}
}

// Should NOT warn: free sync fn does not require async_runtime.
#[cfg(any())]
mod free_sync_fn {
    #[uniffi::export]
    pub fn bar() {}
}

fn main() {}
