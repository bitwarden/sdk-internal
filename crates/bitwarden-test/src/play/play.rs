//! Main Play struct with builder pattern and closure-based cleanup

use std::{future::Future, panic::AssertUnwindSafe, sync::Arc};

use futures::FutureExt;
use uuid::Uuid;

use super::{
    CreateSceneRequest, CreateSceneResponse, PlayConfig, PlayHttpClient, PlayResult, Query,
    QueryRequest, Scene, SceneTemplate,
};

/// Builder for Play instances with closure-based execution
///
/// Use [`Play::builder()`] to create a builder, then chain configuration methods
/// and call [`run()`](PlayBuilder::run) to execute your test with automatic cleanup.
///
/// # Example
///
/// ```ignore
/// use bitwarden_test::play::{Play, SingleUserArgs, SingleUserScene};
///
/// #[tokio::test]
/// async fn test_user_login() {
///     Play::builder()
///         .run(|play| async move {
///             let args = SingleUserArgs {
///                 email: "test@example.com".to_string(),
///                 ..Default::default()
///             };
///             let scene = play.scene::<SingleUserScene>(&args).await.unwrap();
///             // Cleanup happens automatically when run() completes
///         })
///         .await;
/// }
/// ```
pub struct PlayBuilder {
    config: Option<PlayConfig>,
}

impl PlayBuilder {
    /// Create a new builder with default configuration
    fn new() -> Self {
        Self { config: None }
    }

    /// Set custom configuration for the Play instance
    ///
    /// If not called, configuration is loaded from environment variables.
    pub fn config(mut self, config: PlayConfig) -> Self {
        self.config = Some(config);
        self
    }

    /// Run a test with automatic cleanup
    ///
    /// The closure receives a [`Play`] instance and can perform any test operations.
    /// Cleanup is guaranteed to run after the closure completes, regardless of
    /// whether it returns normally or panics.
    ///
    /// # Panics
    ///
    /// If the closure panics, cleanup still runs before the panic is propagated.
    pub async fn run<F, Fut, T>(self, f: F) -> T
    where
        F: FnOnce(Play) -> Fut,
        Fut: Future<Output = T>,
    {
        let config = self.config.unwrap_or_else(PlayConfig::from_env);
        let play = Play::new_internal(config);

        // Execute the closure and catch any panics
        let result = AssertUnwindSafe(f(play.clone())).catch_unwind().await;

        // Always cleanup, regardless of success/failure
        if let Err(e) = play.clean().await {
            tracing::warn!("Play cleanup failed: {:?}", e);
        }

        // Propagate panic or return result
        match result {
            Ok(value) => value,
            Err(panic) => std::panic::resume_unwind(panic),
        }
    }
}

/// The Play test framework for E2E testing
///
/// Provides methods for creating scenes, executing queries, and managing
/// test data with automatic cleanup.
///
/// # Example
///
/// ```ignore
/// use bitwarden_test::play::{Play, SingleUserArgs, SingleUserScene};
///
/// #[tokio::test]
/// async fn test_user_login() {
///     Play::builder()
///         .run(|play| async move {
///             let args = SingleUserArgs {
///                 email: "test@example.com".to_string(),
///                 verified: true,
///                 ..Default::default()
///             };
///             let scene = play.scene::<SingleUserScene>(&args).await.unwrap();
///
///             // Use scene.get_mangled() to look up mangled values
///             let client_id = scene.get_mangled("client_id");
///
///             // Cleanup is automatic when run() completes
///         })
///         .await;
/// }
/// ```
#[derive(Clone)]
pub struct Play {
    client: Arc<PlayHttpClient>,
}

impl Play {
    /// Create a new Play builder
    ///
    /// Use the builder to configure the Play instance and run tests with
    /// automatic cleanup.
    ///
    /// # Example
    ///
    /// ```ignore
    /// Play::builder()
    ///     .run(|play| async move {
    ///         // test code
    ///     })
    ///     .await;
    /// ```
    pub fn builder() -> PlayBuilder {
        PlayBuilder::new()
    }

    /// Internal constructor for creating Play instances
    fn new_internal(config: PlayConfig) -> Self {
        let play_id = Uuid::new_v4().to_string();
        let client = Arc::new(PlayHttpClient::new(play_id, config));
        Play { client }
    }

    /// Create a new scene from template arguments
    ///
    /// The scene data will be cleaned up when the enclosing `run()` completes.
    pub async fn scene<T>(&self, arguments: &T::Arguments) -> PlayResult<Scene<T>>
    where
        T: SceneTemplate,
    {
        let request = CreateSceneRequest {
            template: T::template_name(),
            arguments,
        };

        let response: CreateSceneResponse<T::Result> =
            self.client.post_seeder("/seed/", &request).await?;

        Ok(Scene::new(response.result, response.mangle_map))
    }

    /// Execute a query
    pub async fn query<Q>(&self, arguments: &Q::Args) -> PlayResult<Q>
    where
        Q: Query,
    {
        let request = QueryRequest {
            template: Q::template_name(),
            arguments,
        };

        let result: Q::Result = self.client.post_seeder("/seed/query", &request).await?;

        Ok(Q::from_result(result))
    }

    /// Clean all test data for this play_id
    ///
    /// This is called automatically by [`PlayBuilder::run()`], but can be called
    /// manually if needed.
    pub async fn clean(&self) -> PlayResult<()> {
        self.client
            .delete_seeder(&format!("/seed/{}", self.client.play_id()))
            .await
    }

    /// Get the play_id for this instance
    pub fn play_id(&self) -> &str {
        self.client.play_id()
    }

    /// Get the configuration
    pub fn config(&self) -> &PlayConfig {
        self.client.config()
    }
}

impl Default for PlayBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    /// Creates a Play instance connected to a mock server with DELETE pre-configured.
    async fn play_with_mock_server() -> (Play, MockServer) {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let config = PlayConfig::new(
            "https://api.example.com",
            "https://identity.example.com",
            server.uri(),
        );
        (Play::new_internal(config), server)
    }

    #[tokio::test]
    async fn test_play_instances() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = PlayConfig::new(
            "https://api.example.com",
            "https://identity.example.com",
            server.uri(),
        );

        Play::builder()
            .config(config.clone())
            .run(|play1| async move {
                // Check first instance has valid UUID
                assert!(Uuid::parse_str(play1.play_id()).is_ok());
                assert_eq!(play1.config().seeder_url, server.uri());
            })
            .await;
    }

    #[tokio::test]
    async fn test_unique_play_ids() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;

        let config = PlayConfig::new(
            "https://api.example.com",
            "https://identity.example.com",
            server.uri(),
        );

        let play1 = Play::new_internal(config.clone());
        let play2 = Play::new_internal(config);

        // Each instance has unique UUID
        assert!(Uuid::parse_str(play1.play_id()).is_ok());
        assert!(Uuid::parse_str(play2.play_id()).is_ok());
        assert_ne!(play1.play_id(), play2.play_id());
    }

    // Mock types for testing scene/query functionality
    struct MockScene;

    #[derive(Clone, Serialize)]
    struct MockSceneArgs {
        name: String,
    }

    #[derive(Deserialize)]
    struct MockSceneResult {
        data: String,
    }

    impl SceneTemplate for MockScene {
        type Arguments = MockSceneArgs;
        type Result = MockSceneResult;

        fn template_name() -> &'static str {
            "MockScene"
        }
    }

    #[derive(Debug, Clone)]
    struct MockQuery {
        args: MockQueryArgs,
        value: i32,
    }

    #[derive(Debug, Clone, Serialize)]
    struct MockQueryArgs {
        id: String,
    }

    impl Query for MockQuery {
        type Args = MockQueryArgs;
        type Result = MockQueryResult;

        fn template_name() -> &'static str {
            "MockQuery"
        }

        fn args(&self) -> &Self::Args {
            &self.args
        }

        fn from_result(result: Self::Result) -> Self {
            Self {
                args: MockQueryArgs { id: String::new() },
                value: result.value,
            }
        }
    }

    #[derive(Deserialize)]
    struct MockQueryResult {
        value: i32,
    }

    #[tokio::test]
    async fn test_scene_and_query() {
        let (play, server) = play_with_mock_server().await;

        // Test scene creation
        Mock::given(method("POST"))
            .and(path("/seed/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "data": "test-data" },
                "mangleMap": { "email@example.com": "mangled@example.com" }
            })))
            .mount(&server)
            .await;

        let scene = play
            .scene::<MockScene>(&MockSceneArgs {
                name: "test".into(),
            })
            .await
            .expect("scene creation should succeed");
        assert_eq!(scene.result().data, "test-data");
        assert_eq!(
            scene.get_mangled("email@example.com"),
            "mangled@example.com"
        );

        // Test query execution
        Mock::given(method("POST"))
            .and(path("/seed/query"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(serde_json::json!({ "value": 42 })),
            )
            .mount(&server)
            .await;

        let result = play
            .query::<MockQuery>(&MockQueryArgs { id: "test".into() })
            .await
            .expect("query should succeed");
        assert_eq!(result.value, 42);
    }

    #[tokio::test]
    async fn test_server_error_handling() {
        let (play, server) = play_with_mock_server().await;

        Mock::given(method("POST"))
            .and(path("/seed/"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let result = play
            .scene::<MockScene>(&MockSceneArgs {
                name: "test".into(),
            })
            .await;

        assert!(matches!(
            result,
            Err(super::super::PlayError::ServerError { status: 500, .. })
        ));
    }

    #[tokio::test]
    async fn test_builder_runs_cleanup() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let config = PlayConfig::new(
            "https://api.example.com",
            "https://identity.example.com",
            server.uri(),
        );

        Play::builder()
            .config(config)
            .run(|_play| async move {
                // Test completes normally
            })
            .await;

        // The mock server will verify DELETE was called exactly once
    }

    #[tokio::test]
    async fn test_clean() {
        let server = MockServer::start().await;
        Mock::given(method("DELETE"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let config = PlayConfig::new(
            "https://api.example.com",
            "https://identity.example.com",
            server.uri(),
        );
        let play = Play::new_internal(config);

        assert!(play.clean().await.is_ok());
    }
}
