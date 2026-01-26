//! Play test framework for E2E testing
//!
//! This module provides a scene-based testing framework.
//!
//! # Overview
//!
//! The Play framework enables E2E testing by:
//! - Creating test data via a seeder API
//! - Providing test isolation through unique play IDs
//! - Automatic cleanup when scenes are dropped

mod config;
mod error;
mod http_client;
#[allow(clippy::module_inception)]
mod play;
mod query;
mod scene;
mod scene_template;

pub mod scenes;

pub use config::PlayConfig;
pub use error::{PlayError, PlayResult};
pub use http_client::PlayHttpClient;
pub use play::Play;
pub use query::Query;
pub(crate) use query::QueryRequest;
pub use scene::Scene;
pub use scene_template::SceneTemplate;
pub(crate) use scene_template::{CreateSceneRequest, CreateSceneResponse};
pub use scenes::{SingleUserArgs, SingleUserScene};
