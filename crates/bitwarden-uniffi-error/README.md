# Bitwarden UniFFI error

Routes the errors produced inside `uniffi::custom_type!` conversions into the single error type the
UniFFI bindings return, so invalid input from Kotlin or Swift surfaces as a catchable
`BitwardenException` instead of an internal error.

## Why this exists

UniFFI converts each argument into its Rust type before calling an exported function, which for a
custom type runs the fallible `try_lift` closure from `uniffi::custom_type!`. It reports a failure
by downcasting the error to the type in the exported function's signature
(`LowerReturn::handle_failed_lift`). The downcast is on the concrete type, so a `From` conversion
does not help: when the types don't match, the client gets an undeclared internal error instead of
the typed exception it knows how to catch.

`set_error_to_uniffi_error` installs a process-wide converter, `convert_result` applies it, and
`bitwarden-uniffi` registers one producing `BitwardenError::Conversion`. Two rules follow, neither
enforced by the compiler or a lint:

1. Every `uniffi::custom_type!` must pass its `try_lift` result through `convert_result`. Relying on
   the default `TryFrom`-based lift, or returning the crate's own error, bypasses the converter.
2. Every UniFFI-exported function must return `BitwardenError`. It is defined in `bitwarden-uniffi`,
   which depends on the feature crates and not the other way round, so a feature crate cannot name
   it and the export has to live in `bitwarden-uniffi` behind a wrapper client.

Rule 2 only looks avoidable. An export elsewhere is safe exactly while none of its arguments involve
a fallible custom type, including nested ones, since a `uniffi::Record` field pulls in that field's
lift.

## Upstream limitation

Without the limitation, a feature crate would export its client over UniFFI the same way it already
does over WASM, keeping the bindings next to the implementation and returning its own error type.
That is the pattern we want everywhere.

It is tracked upstream at <https://github.com/mozilla/uniffi-rs/issues/2416>. If it is lifted, both
this crate and the wrapper clients become unnecessary. The only alternative today is a single shared
error type in a foundation crate that every feature crate can return, which costs all domain error
detail on the mobile surface.
