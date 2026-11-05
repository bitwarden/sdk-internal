//! End-to-end tests: the real connector against a live server, with state seeded through the
//! Seeder API. They need the server stack and SeederApi running, so `cargo test` skips this
//! target; see the README's `## Development` section.

#![allow(dead_code)]

mod common;

#[path = "e2e"]
mod e2e {
    pub mod cipher;
    pub mod fixture;
    pub mod runner;
    pub mod scenes;

    mod rotation_outcomes;
    mod rotation_success;
    mod server_contract;
}
