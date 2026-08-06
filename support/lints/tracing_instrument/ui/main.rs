// Real compilation: LateLintPass runs after macro expansion, so the test fixture must
// actually build against `tracing` and `bitwarden_logging_macro`.

#![warn(tracing_instrument)]
#![allow(dead_code)]

// Should warn with MachineApplicable suggestion: pure path swap, no args.
mod qualified_tracing {
    #[tracing::instrument]
    fn foo() {}
}

// Should warn with MachineApplicable suggestion: pass-through args (no `skip(...)`).
mod with_pass_through_args {
    #[tracing::instrument(err, level = "debug")]
    fn foo() -> Result<(), &'static str> {
        Ok(())
    }
}

// Should warn with MachineApplicable suggestion: `skip_all` is dropped (the wrapper
// already enforces it and rejects an explicit `skip_all`).
mod with_skip_all {
    #[tracing::instrument(skip_all, err)]
    fn foo(secret: &str) -> Result<(), &'static str> {
        let _ = secret;
        Ok(())
    }
}

// Should warn with HELP only (no suggestion): `skip(...)` needs human judgment to
// translate into `fields(...)` opt-ins.
mod with_skip_list {
    #[tracing::instrument(skip(secret), err)]
    fn foo(secret: &str, public: u32) -> Result<(), &'static str> {
        let _ = (secret, public);
        Ok(())
    }
}

// Should warn: bare `#[instrument]` after `use tracing::instrument` is still caught by
// macro identity. (Auto-fix here leaves a now-unused import; that's fine — `cargo fix`
// will clean it up on a subsequent pass.)
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
