//! Query trait for parameterized database queries

use serde::{Serialize, de::DeserializeOwned};

/// Trait for defining parameterized queries
///
/// Queries allow executing specific operations against the test database.
pub trait Query: Sized + Send + Sync {
    /// The type of arguments passed to the query
    type Args: Serialize + Clone + Send + Sync;

    /// The type of result returned by the query
    type Result: DeserializeOwned + Send + Sync;

    /// The name of this query template
    fn template_name() -> &'static str;

    /// Get the arguments for this query
    fn args(&self) -> &Self::Args;

    /// Create an instance from the query result
    fn from_result(result: Self::Result) -> Self;
}

/// Request body for executing a query
#[derive(Serialize)]
pub(crate) struct QueryRequest<'a, A: Serialize> {
    pub template: &'a str,
    pub arguments: &'a A,
}
