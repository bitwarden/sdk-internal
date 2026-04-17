//! Compatibility adapter that runs a future on a dedicated multi-threaded tokio runtime.
//!
//! # Why this crate exists
//!
//! This crate replaces the upstream [`async-compat`] via the workspace's `[patch.crates-io]`.
//! `uniffi`'s `#[uniffi::export(async_runtime = "tokio")]` macro wraps exported futures in
//! `async_compat::Compat::new(...)`; the upstream implementation polls the inner future on
//! whatever thread calls `rust_future_poll`, which on mobile hosts (Android, iOS) is typically
//! the UI/main thread. That thread must not block on I/O — Android in particular throws
//! `NetworkOnMainThreadException` for network calls from the main thread.
//!
//! Our replacement spawns the wrapped future onto a dedicated multi-threaded tokio runtime, so
//! the caller's thread only polls the resulting `JoinHandle` and wakes when the task completes.
//! The caller thread never executes the future's body.
//!
//! See [`Compat`] for behavior, lifetime, and leak caveats.
//!
//! # Sanitizer runs
//!
//! The unsafe lifetime transmute in [`Compat::new`] can be validated for
//! use-after-free and heap-overflow regressions using AddressSanitizer.
//! ASAN is silent on success; any detection prints a report and exits non-zero.
//!
//! ```text
//! RUSTFLAGS=-Zsanitizer=address cargo +nightly test \
//!     --target aarch64-apple-darwin -Zbuild-std -p async-compat
//! ```
//!
//! Swap the `--target` triple as appropriate for other hosts.
//!
//! [`async-compat`]: https://crates.io/crates/async-compat

use std::{
    future::Future,
    panic,
    pin::Pin,
    sync::LazyLock,
    task::{Context, Poll},
};

use tokio::{runtime::Runtime, task::JoinHandle};

/// Used to assert UniFFI is using our version of the crate.
#[doc(hidden)]
pub const __BITWARDEN_PATCHED: () = ();

static RUNTIME: LazyLock<Runtime> = LazyLock::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .thread_name("async-compat-worker")
        .enable_all()
        .build()
        .expect("cannot start async-compat tokio runtime")
});

/// Runs a future on a dedicated multi-threaded tokio runtime, guaranteeing it is polled
/// on a background worker thread and never on the caller's thread.
///
/// Dropping a `Compat` before the task completes aborts it and blocks the current thread until the
/// runtime has dropped the spawned future. This is required for soundness when the inner future
/// borrows from the caller's scope.
///
/// # Lifetime tracking
///
/// [`Compat::new`] accepts non-`'static` futures. The borrow checker still prevents the
/// wrapper from outliving any borrows captured inside the future:
///
/// ```compile_fail
/// let compat;
/// {
///     let s = String::from("hello");
///     compat = async_compat::Compat::new(async { s.len() });
/// }
/// // Would be unsound: `s` is dropped but `compat` wraps a future that borrowed `s`.
/// let _ = futures::executor::block_on(compat);
/// ```
///
/// A `Compat` around a borrowed future is not `'static`:
///
/// ```compile_fail
/// fn assert_static<T: 'static>(_: T) {}
/// let s = String::from("hello");
/// assert_static(async_compat::Compat::new(async { s.len() }));
/// ```
///
/// # Leak safety
///
/// Soundness relies on `Drop` running. Leaking a `Compat` that holds a non-`'static`
/// future (via [`std::mem::forget`], [`Box::leak`], or a reference cycle) lets the
/// spawned task outlive its borrow, which is UB. Same caveat [`async-scoped`] documents in its
/// [Safety Considerations]. Semantically `Compat` is like `async-scoped`'s
/// [`scope_and_collect`]: an async wrapper that must be driven to completion or dropped.
///
/// [`async-scoped`]: https://docs.rs/async-scoped/0.9.0/async_scoped/
/// [Safety Considerations]: https://docs.rs/async-scoped/0.9.0/async_scoped/#safety-considerations
/// [`scope_and_collect`]: https://docs.rs/async-scoped/0.9.0/async_scoped/struct.Scope.html#method.scope_and_collect
pub struct Compat<F: Future>
where
    F::Output: Send + 'static,
{
    // `Some` until the handle resolves (whether with a value or a panic) or `Drop` runs.
    handle: Option<JoinHandle<F::Output>>,
}

impl<F> Compat<F>
where
    F: Future + Send,
    F::Output: Send + 'static,
{
    /// Spawns `future` on the dedicated runtime and returns a wrapper that resolves
    /// to the future's output when awaited.
    pub fn new(future: F) -> Self {
        // Trait-object the future so the struct doesn't need to carry `F`'s lifetime directly.
        let boxed: Pin<Box<dyn Future<Output = F::Output> + Send + '_>> = Box::pin(future);
        // SAFETY: `future` may borrow from the caller's scope, but `tokio::spawn` requires
        // `F: 'static`, so we transmute the boxed future to `'static` to satisfy that bound.
        // This is safe as long as the future never actually outlives its original lifetime,
        // which we guarantee by upholding these invariants:
        //   1. `Compat<F>` is generic over `F`, so it inherits `F`'s lifetime bound — the borrow
        //      checker forbids a `Compat<F>` from outliving whatever `F` borrows.
        //   2. `Drop` aborts the task and blocks on the `JoinHandle` until the runtime has dropped
        //      the spawned future, ensuring any data it borrowed is no longer being accessed.
        //   3. The caller must not leak `Compat` (`mem::forget`, cycles, etc.); leaking skips
        //      `Drop` and lets the task outlive its borrow.
        //
        // Same pattern as `async-scoped`:
        //   https://docs.rs/async-scoped/0.9.0/src/async_scoped/scoped.rs.html#60-64
        //   https://docs.rs/async-scoped/0.9.0/src/async_scoped/scoped.rs.html#154-168
        let boxed: Pin<Box<dyn Future<Output = F::Output> + Send + 'static>> =
            unsafe { std::mem::transmute(boxed) };
        Self {
            handle: Some(RUNTIME.spawn(boxed)),
        }
    }
}

impl<F: Future> Drop for Compat<F>
where
    F::Output: Send + 'static,
{
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // Already done: the runtime has dropped the inner future and released any borrows.
            if handle.is_finished() {
                return;
            }
            handle.abort();
            // SAFETY: Block until the runtime has dropped the spawned future, so any borrows it
            // held are released before `drop` returns. Using `futures` instead of `tokio` to block
            // on the handle avoids re-entering the runtime's context which causes a panic.
            let _ = futures::executor::block_on(handle);
        }
    }
}

impl<F> Future for Compat<F>
where
    F: Future + Send,
    F::Output: Send + 'static,
{
    type Output = F::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<F::Output> {
        let this = Pin::into_inner(self);
        let handle = this
            .handle
            .as_mut()
            .expect("Compat polled after completion");

        match Pin::new(handle).poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(result) => {
                // Clear the handle so `Drop` doesn't try to abort it
                this.handle = None;
                match result {
                    Ok(out) => Poll::Ready(out),
                    Err(e) if e.is_panic() => panic::resume_unwind(e.into_panic()),
                    // The only way `JoinHandle` can error without panicking is if the runtime is
                    // shutting down, which can never happen since `RUNTIME` is static.
                    Err(e) => panic!("async-compat task ended unexpectedly: {e}"),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::Future,
        pin::pin,
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
        },
        task::{Context, Poll, Waker},
        thread::{self, ThreadId},
        time::Duration,
    };

    use crate::Compat;

    #[test]
    fn returns_inner_output() {
        let value = futures::executor::block_on(Compat::new(async { 42 }));
        assert_eq!(value, 42);
    }

    #[test]
    fn runs_on_worker_thread_not_caller() {
        let caller = thread::current().id();

        let observed: Arc<Mutex<Option<ThreadId>>> = Arc::new(Mutex::new(None));

        for i in 0..25 {
            let observed_clone = observed.clone();
            futures::executor::block_on(Compat::new(async move {
                *observed_clone.lock().unwrap() = Some(thread::current().id());
            }));

            let worker = observed.lock().unwrap().unwrap();
            assert_ne!(caller, worker, "iteration {i} ran on the caller thread");
        }
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn panics_propagate_to_caller() {
        futures::executor::block_on(Compat::new(async { panic!("boom") }));
    }

    #[test]
    fn drop_after_spawn_aborts_task() {
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();

        let compat = Compat::new(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            done_clone.store(true, Ordering::SeqCst);
        });

        {
            let mut compat = pin!(compat);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(compat.as_mut().poll(&mut cx), Poll::Pending));
        } // Drop blocks until the task is aborted.

        thread::sleep(Duration::from_millis(200));
        assert!(
            !done.load(Ordering::SeqCst),
            "task should have been aborted"
        );
    }

    #[test]
    fn accepts_non_static_borrowed_future() {
        let local = String::from("hello");
        let output = futures::executor::block_on(Compat::new(async { format!("{local} world") }));
        assert_eq!(output, "hello world");
    }

    #[test]
    fn compat_is_send_and_sync_when_inner_is() {
        // Compile-time check: uniffi requires Send + Sync on the wrapped future.
        fn assert_send_sync<T: Send + Sync>(_: &T) {}
        let compat = Compat::new(async { 42 });
        assert_send_sync(&compat);
    }

    #[test]
    fn many_concurrent_compats() {
        // Stress the fixed 4-worker pool: spawn more tasks than workers and verify
        // they all complete with the right output.
        let handles: Vec<_> = (0..64)
            .map(|i| {
                std::thread::spawn(move || {
                    futures::executor::block_on(Compat::new(async move {
                        tokio::task::yield_now().await;
                        i * 2
                    }))
                })
            })
            .collect();

        for (i, h) in handles.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), i * 2);
        }
    }

    #[test]
    fn drop_before_first_poll() {
        // Compat::new spawns eagerly, so the task may already be running by the time
        // we drop it without ever polling. Drop must still abort cleanly.
        let done = Arc::new(AtomicBool::new(false));
        let done_clone = done.clone();
        let compat = Compat::new(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            done_clone.store(true, Ordering::SeqCst);
        });
        drop(compat);
        thread::sleep(Duration::from_millis(200));
        assert!(
            !done.load(Ordering::SeqCst),
            "task should have been aborted"
        );
    }

    #[test]
    fn borrowed_data_still_valid_after_drop() {
        // Direct test of the transmute safety contract: if the task borrows `data`
        // and is aborted during Drop, the block-on wait ensures the borrow is
        // released before control returns. `data` is read after drop.
        let data = String::from("borrowed");
        {
            let compat = Compat::new(async {
                tokio::time::sleep(Duration::from_secs(60)).await;
                data.len() // borrows `data`
            });
            let mut compat = pin!(compat);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(compat.as_mut().poll(&mut cx), Poll::Pending));
        } // Drop aborts + blocks until the task unwinds and drops the borrow.
        assert_eq!(data, "borrowed");
    }

    #[test]
    fn drop_from_inside_tokio_runtime() {
        // Regression: Drop must not panic when called from inside a tokio runtime.
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();

        rt.block_on(async {
            let compat = Compat::new(async move {
                tokio::time::sleep(Duration::from_millis(50)).await;
            });

            let mut compat = pin!(compat);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(compat.as_mut().poll(&mut cx), Poll::Pending));
            // Drop fires at end of scope, from inside `rt`'s worker. Must not panic.
        });
    }

    #[test]
    fn uniffi_scenario() {
        // Mimics uniffi's macro expansion: an outer `'static` async move that wraps a
        // non-`'static` method call in `Compat`. If this works, the integration works.
        struct Service {
            name: String,
        }
        impl Service {
            async fn greet(&self) -> String {
                tokio::task::yield_now().await;
                format!("hello, {}", self.name)
            }
        }

        let service = Arc::new(Service {
            name: "world".into(),
        });
        let outer = async move { Compat::new(service.greet()).await };

        assert_eq!(futures::executor::block_on(outer), "hello, world");
    }

    #[test]
    #[should_panic(expected = "Compat polled after completion")]
    fn poll_after_ready_panics() {
        // Polling after `Ready` is a contract violation; we panic rather than silently misbehave.
        let mut compat = pin!(Compat::new(async { 1u8 }));
        assert_eq!(futures::executor::block_on(compat.as_mut()), 1);
        let mut cx = Context::from_waker(Waker::noop());
        let _ = compat.as_mut().poll(&mut cx);
    }

    #[test]
    fn drop_waits_for_task_to_release_borrow() {
        {
            let data = vec![0u8; 1024];
            let compat = Compat::new(async {
                // This task can't be aborted and will always complete.
                std::thread::sleep(Duration::from_millis(50));
                let _ = std::hint::black_box(data[0]);
            });
            let mut compat = pin!(compat);
            let mut cx = Context::from_waker(Waker::noop());
            assert!(matches!(compat.as_mut().poll(&mut cx), Poll::Pending));
            // drop(compat) runs here, and must block until the task is complete
            // to ensure data is not freed before the task is done.
        }
        thread::sleep(Duration::from_millis(100));
    }
}
