#[derive(Debug, thiserror::Error)]
enum ApiError {
    #[error("network")]
    NetworkError,
    #[error("timeout")]
    TimeoutError,
    #[error("parse")]
    ParseError,
}

#[derive(Debug, thiserror::Error)]
enum DatabaseError {
    #[error("connection")]
    ConnectionError,
    #[error("query")]
    QueryError,
}

#[derive(Debug, thiserror::Error)]
enum GoodEnum {
    #[error("network")]
    Network,
    #[error("timeout")]
    Timeout,
    #[error("parse")]
    Parse,
}

#[derive(Debug, thiserror::Error)]
enum MixedEnum {
    #[error("success")]
    Success,
    #[error("failure")]
    FailureError,
    #[error("invalid")]
    InvalidError,
    #[error("retry")]
    Retry,
}

fn main() {}
