//! Suppression of Flight Recorder capture while a future is polled.

use std::{
    cell::Cell,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

thread_local! {
    static SUPPRESSED: Cell<bool> = const { Cell::new(false) };
}

/// Whether capture is suppressed on the current thread.
pub(crate) fn is_suppressed() -> bool {
    SUPPRESSED.with(Cell::get)
}

/// Runs `future` without recording any events it emits while being polled, from any crate or
/// target. Work the future hands to other spawned tasks is not covered.
///
/// Used by code that sends Flight Recorder events, so that events produced by the sending itself
/// are not captured and sent again.
pub fn without_flight_recorder<F: Future>(future: F) -> impl Future<Output = F::Output> {
    Suppressed {
        inner: Box::pin(future),
    }
}

struct Suppressed<F> {
    inner: Pin<Box<F>>,
}

impl<F: Future> Future for Suppressed<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let previous = SUPPRESSED.with(|s| s.replace(true));
        let result = self.inner.as_mut().poll(cx);
        SUPPRESSED.with(|s| s.set(previous));
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_suppressed_only_while_polled() {
        assert!(!is_suppressed());
        let inside = without_flight_recorder(async { is_suppressed() }).await;
        assert!(inside);
        assert!(!is_suppressed());
    }
}
