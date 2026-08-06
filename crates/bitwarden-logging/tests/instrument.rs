//! Behavior tests for `bitwarden_logging::instrument`.
//!
//! The wrapper rewrites to `#[tracing::instrument(skip_all, ...)]`, so all function
//! arguments should be excluded from span fields unless explicitly opted in via `fields(...)`.

use std::{
    io,
    sync::{Arc, Mutex},
};

use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

#[derive(Clone, Default)]
struct CapturedWriter(Arc<Mutex<Vec<u8>>>);

impl CapturedWriter {
    fn into_string(self) -> String {
        let bytes = self.0.lock().expect("writer poisoned").clone();
        String::from_utf8(bytes).expect("non-utf8 in captured output")
    }
}

impl io::Write for CapturedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .expect("writer poisoned")
            .extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for CapturedWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn with_capture<F: FnOnce()>(f: F) -> String {
    let writer = CapturedWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(writer.clone())
        .with_max_level(Level::TRACE)
        .with_ansi(false)
        .finish();
    tracing::subscriber::with_default(subscriber, f);
    writer.into_string()
}

#[bitwarden_logging::instrument]
fn args_skipped_by_default(password: &str, email: &str) {
    tracing::info!("inside");
    let _ = (password, email);
}

#[bitwarden_logging::instrument(fields(email = email))]
fn explicit_field_opt_in(password: &str, email: &str) {
    tracing::info!("inside");
    let _ = password;
}

#[bitwarden_logging::instrument(name = "renamed", level = "debug")]
fn name_and_level_passthrough(value: i32) {
    tracing::debug!("inside");
    let _ = value;
}

#[bitwarden_logging::instrument(err)]
fn err_passthrough(should_fail: bool) -> Result<(), &'static str> {
    if should_fail { Err("boom") } else { Ok(()) }
}

// Compile-only check: the wrapper must expand correctly for `async fn` bodies. Whether the
// future is awaited is irrelevant for testing the expansion shape.
#[bitwarden_logging::instrument]
#[allow(dead_code)]
async fn async_expansion_compiles(secret: &str) {
    tracing::info!("inside");
    let _ = secret;
}

// Compile-only check: the wrapper must expand correctly for generic functions.
#[bitwarden_logging::instrument]
#[allow(dead_code)]
fn generic_expansion_compiles<T: std::fmt::Debug>(value: T) {
    tracing::info!("inside");
    let _ = value;
}

#[test]
fn arguments_are_skipped_by_default() {
    let output = with_capture(|| args_skipped_by_default("hunter2", "user@example.com"));
    assert!(
        !output.contains("hunter2"),
        "password leaked into span output:\n{output}"
    );
    assert!(
        !output.contains("user@example.com"),
        "email leaked into span output:\n{output}"
    );
}

#[test]
fn fields_opt_in_is_recorded() {
    let output = with_capture(|| explicit_field_opt_in("hunter2", "user@example.com"));
    assert!(
        output.contains("user@example.com"),
        "explicit email field missing:\n{output}"
    );
    assert!(
        !output.contains("hunter2"),
        "password leaked despite no opt-in:\n{output}"
    );
}

#[test]
fn name_and_level_flow_through() {
    let output = with_capture(|| name_and_level_passthrough(42));
    assert!(
        output.contains("renamed"),
        "renamed span name missing:\n{output}"
    );
    // tracing renders recorded fields as `name=value`; absence of the field marker confirms
    // the argument was not recorded. (Avoiding a bare `"42"` substring check because
    // timestamps can spuriously match short numeric values.)
    assert!(
        !output.contains("value=42"),
        "argument value leaked into span:\n{output}"
    );
}

#[test]
fn err_flag_records_errors_on_failure() {
    let output = with_capture(|| {
        let _ = err_passthrough(true);
    });
    assert!(
        output.contains("boom"),
        "err return value missing from span:\n{output}"
    );
}

#[test]
fn err_flag_stays_quiet_on_success() {
    let output = with_capture(|| {
        let _ = err_passthrough(false);
    });
    assert!(
        !output.contains("boom"),
        "unexpected error text on success path:\n{output}"
    );
}

#[test]
fn compile_fail_cases() {
    let t = trybuild::TestCases::new();
    t.compile_fail("tests/compilation_tests/skip_forbidden.rs");
    t.compile_fail("tests/compilation_tests/skip_all_forbidden.rs");
    t.compile_fail("tests/compilation_tests/skip_and_skip_all.rs");
}
