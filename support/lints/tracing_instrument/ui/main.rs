// The lint defaults to `allow` so existing workspace call sites have time to migrate.
// Opt in here so the test fixture actually exercises the lint logic.
#![warn(tracing_instrument)]

// Each case lives in its own `#[cfg(any())]` module so it is parsed by the
// pre-expansion lint pass but never compiled. This lets us reference
// `#[tracing::instrument]` without pulling `tracing` in as a dev-dependency.

// Should warn: bare `#[tracing::instrument]`.
#[cfg(any())]
mod tracing_instrument_no_args {
    #[tracing::instrument]
    pub fn foo() {}
}

// Should warn: `#[tracing::instrument]` with arguments.
#[cfg(any())]
mod tracing_instrument_with_args {
    #[tracing::instrument(skip(self), err)]
    pub fn foo() {}
}

// Should NOT warn: `#[bitwarden_logging::instrument]` is the blessed form.
#[cfg(any())]
mod bitwarden_logging_instrument {
    #[bitwarden_logging::instrument]
    pub fn foo() {}
}

// Should warn: bare `#[instrument]` (e.g. via `use tracing::instrument;`) is the classic
// way to silently re-introduce the foot-gun. The convention is to always fully qualify.
#[cfg(any())]
mod bare_instrument {
    #[instrument]
    pub fn foo() {}
}

// Should NOT warn: an attribute that merely ends in `instrument` but lives elsewhere.
#[cfg(any())]
mod other_instrument {
    #[some_other_crate::instrument]
    pub fn foo() {}
}

fn main() {}
