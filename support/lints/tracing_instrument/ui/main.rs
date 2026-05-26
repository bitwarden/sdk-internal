// Real compilation: LateLintPass runs after macro expansion, so the test fixture must
// actually build against `tracing` and `bitwarden_logging_macro`.

#![warn(tracing_instrument)]
#![allow(dead_code)]

// Should warn: fully-qualified `tracing::instrument`.
mod qualified_tracing {
    #[tracing::instrument]
    fn foo() {}
}

// Should warn: bare `#[instrument]` after `use tracing::instrument`.
mod imported_tracing {
    use tracing::instrument;

    #[instrument]
    fn foo() {}
}

// Should warn: aliased `tracing::instrument` import.
mod aliased_tracing {
    use tracing::instrument as renamed;

    #[renamed]
    fn foo() {}
}

// Should NOT warn: `bitwarden_logging::instrument` is the blessed wrapper, even though it
// internally expands to `tracing::instrument` — the lint filters out expansions that came
// through `bitwarden_logging_macro`.
mod wrapper {
    #[bitwarden_logging_macro::instrument]
    fn foo(secret: &str) {
        let _ = secret;
    }
}

fn main() {}
