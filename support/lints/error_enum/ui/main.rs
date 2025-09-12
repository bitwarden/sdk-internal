enum ApiError {
    NetworkError,
    TimeoutError,
    ParseError,
}

enum DatabaseError {
    ConnectionError,
    QueryError,
}

enum GoodEnum {
    Network,
    Timeout,
    Parse,
}

enum MixedEnum {
    Success,
    FailureError,
    InvalidError,
    Retry,
}

fn main() {}
