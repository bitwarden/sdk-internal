//! Play test framework for E2E testing
//!
//! This module provides a scene-based testing framework with automatic cleanup.
//!
//! # Overview
//!
//! The Play framework enables E2E testing by:
//! - Creating test data via a seeder API
//! - Providing test isolation through unique play IDs
//! - Automatic cleanup when the test closure completes
//!
//! # Example
//!
//! ```ignore
//! use bitwarden_test::play::{play_test, Play, SingleUserArgs, SingleUserScene};
//!
//! #[play_test]
//! async fn test_user_login(play: Play) {
//!     let args = SingleUserArgs {
//!         email: "test@example.com".to_string(),
//!         ..Default::default()
//!     };
//!     let scene = play.scene::<SingleUserScene>(&args).await.unwrap();
//!     // Cleanup happens automatically
//! }
//! ```

mod config;
mod error;
mod http_client;
#[allow(clippy::module_inception)]
mod play;
mod query;
mod scene;
mod scene_template;

pub mod scenes;

pub use bitwarden_test_macro::play_test;
pub use config::PlayConfig;
pub use error::{PlayError, PlayResult};
pub(crate) use http_client::PlayHttpClient;
pub use play::{Play, PlayBuilder};
pub use query::Query;
pub(crate) use query::QueryRequest;
pub use scene::Scene;
pub use scene_template::SceneTemplate;
pub(crate) use scene_template::{CreateSceneRequest, CreateSceneResponse};
pub use scenes::{SingleUserArgs, SingleUserScene};
