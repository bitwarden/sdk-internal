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
