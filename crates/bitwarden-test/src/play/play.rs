//! Main Play struct with instance-based design and automatic cleanup

use std::sync::Arc;

use uuid::Uuid;

use super::{
    CreateSceneRequest, CreateSceneResponse, PlayConfig, PlayHttpClient, PlayResult, Query,
    QueryRequest, Scene, SceneTemplate,
};

/// Generate a new unique play_id (first 8 chars of UUID)
fn generate_play_id() -> String {
    Uuid::new_v4().to_string()
}

/// The Play test framework for E2E testing
///
/// Provides methods for creating scenes, executing queries, and managing
/// test data with automatic cleanup when dropped.
///
/// # Example
///
/// ```ignore
/// use bitwarden_test::play::{Play, SingleUserScene, SingleUserBuilder};
///
/// #[tokio::test]
/// async fn test_user_login() {
///     let play = Play::new();
///
///     // Provide base email - the seeder mangles it server-side
///     let args = SingleUserBuilder::new("test@example.com")
///         .verified(true)
///         .build();
///     let scene = play.scene::<SingleUserScene>(&args).await.unwrap();
///
///     // Use scene.inner() to access mangled user data from server
///     let user = scene.inner();
///     let (client_id, client_secret) = user.api_key();
///
///     // All scenes are automatically cleaned up when `play` is dropped
/// }
/// ```
pub struct Play {
    client: Arc<PlayHttpClient>,
}

impl Play {
    /// Create a new Play instance with a unique play_id
    ///
    /// Configuration is loaded from environment variables.
    /// All test data created through this instance will be cleaned up when dropped.
    pub fn new() -> Self {
        let play_id = generate_play_id();
        let config = PlayConfig::from_env();
        let client = Arc::new(PlayHttpClient::new(play_id, config));

        Play { client }
    }

    /// Create a new Play instance with custom configuration
    ///
    /// All test data created through this instance will be cleaned up when dropped.
    pub fn new_with_config(config: PlayConfig) -> Self {
        let play_id = generate_play_id();
        let client = Arc::new(PlayHttpClient::new(play_id, config));

        Play { client }
    }

    /// Create a new scene from template arguments
    ///
    /// The scene data will be cleaned up when this Play instance is dropped.
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

        let template_instance = T::from_result(response.result);

        Ok(Scene::new(template_instance, response.mangle_map))
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

    /// Manually clean all test data for this play_id
    ///
    /// This is called automatically when the Play instance is dropped.
    pub async fn clean(&self) -> PlayResult<()> {
        self.client
            .delete_seeder(&format!("/seed/{}", self.client.play_id()))
            .await
    }

    /// Get the play_id for this instance
    pub fn play_id(&self) -> &str {
        self.client.play_id()
    }

    /// Get the HTTP client for advanced operations
    pub fn http_client(&self) -> Arc<PlayHttpClient> {
        self.client.clone()
    }

    /// Get the configuration
    pub fn config(&self) -> &PlayConfig {
        self.client.config()
    }
}

impl Default for Play {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for Play {
    fn drop(&mut self) {
        let client = self.client.clone();
        let play_id = client.play_id().to_string();

        // Use the current runtime to run cleanup synchronously
        let handle = tokio::runtime::Handle::current();
        let _ = tokio::task::block_in_place(|| {
            handle.block_on(async { client.delete_seeder(&format!("/seed/{}", play_id)).await })
        });
    }
}

#[cfg(test)]
mod tests {
    use std::mem::ManuallyDrop;

    use serde::{Deserialize, Serialize};
    use wiremock::{
        Mock, MockServer, ResponseTemplate,
        matchers::{method, path},
    };

    use super::*;

    /// Test helper that wraps Play and prevents Drop cleanup.
    fn test_play(seeder_url: &str) -> ManuallyDrop<Play> {
        let config = PlayConfig::new(
            "https://api.example.com",
            "https://identity.example.com",
            seeder_url,
        );
        ManuallyDrop::new(Play::new_with_config(config))
    }

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
        (Play::new_with_config(config), server)
    }

    #[test]
    fn test_play_instances() {
        let play1 = test_play("http://localhost:5047");
        let play2 = test_play("http://localhost:5047");

        // Each instance has a valid, unique UUID
        assert!(Uuid::parse_str(play1.play_id()).is_ok());
        assert!(Uuid::parse_str(play2.play_id()).is_ok());
        assert_ne!(play1.play_id(), play2.play_id());

        // Accessors work correctly
        assert_eq!(play1.config().seeder_url, "http://localhost:5047");
        assert_eq!(play1.http_client().play_id(), play1.play_id());
    }

    // Mock types for testing scene/query functionality
    #[derive(Debug, Clone)]
    struct MockScene {
        data: String,
    }

    #[derive(Clone, Serialize)]
    struct MockSceneArgs {
        name: String,
    }

    impl SceneTemplate for MockScene {
        type Arguments = MockSceneArgs;
        type Result = MockSceneResult;

        fn template_name() -> &'static str {
            "MockScene"
        }

        fn from_result(result: Self::Result) -> Self {
            Self { data: result.data }
        }
    }

    #[derive(Deserialize)]
    struct MockSceneResult {
        data: String,
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

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn test_scene_and_query() {
        let (play, server) = play_with_mock_server().await;

        // Test scene creation
        Mock::given(method("POST"))
            .and(path("/seed/"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "result": { "data": "test-data" },
                "mangleMap": { "email": "mangled@example.com" }
            })))
            .mount(&server)
            .await;

        let scene = play
            .scene::<MockScene>(&MockSceneArgs {
                name: "test".into(),
            })
            .await
            .unwrap();
        assert_eq!(scene.inner().data, "test-data");
        assert_eq!(scene.get_mangled("email"), "mangled@example.com");

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
            .unwrap();
        assert_eq!(result.value, 42);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
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
        let play = Play::new_with_config(config);

        assert!(play.clean().await.is_ok());
        std::mem::forget(play); // Avoid double cleanup in Drop
    }
}
