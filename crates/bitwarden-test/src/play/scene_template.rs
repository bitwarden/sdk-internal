//! SceneTemplate trait for defining test scenes

use std::collections::HashMap;

use serde::{Serialize, de::DeserializeOwned};

/// Trait for defining scene templates
///
/// Scene templates define how to create and tear down test data.
/// Each template has associated types for input arguments and output results.
pub trait SceneTemplate {
    /// The type of arguments passed to create the scene
    type Arguments: Serialize + Clone + Send + Sync;

    /// The type of result returned when the scene is created
    type Result: DeserializeOwned + Send + Sync;

    /// The name of this template (used in API calls)
    fn template_name() -> &'static str;
}

/// Request body for creating a scene
#[derive(Serialize)]
pub(crate) struct CreateSceneRequest<'a, A: Serialize> {
    pub template: &'a str,
    pub arguments: &'a A,
}

/// Response from creating a scene
#[derive(serde::Deserialize)]
pub(crate) struct CreateSceneResponse<R> {
    pub result: R,
    #[serde(rename = "mangleMap", default)]
    pub mangle_map: HashMap<String, String>,
}
