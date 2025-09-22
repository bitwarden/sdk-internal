#[derive(Debug, thiserror::Error)]
#[error("Bad example error")]
struct BadExample {}

#[derive(Debug, thiserror::Error)]
#[error("Good example error")]
struct GoodExampleError {}

#[derive(Debug)]
struct BadManualExample {}

impl std::fmt::Display for BadManualExample {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Bad manual example error")
    }
}

impl std::error::Error for BadManualExample {}

#[derive(Debug)]
struct GoodManualError {}

impl std::fmt::Display for GoodManualError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Good manual error")
    }
}

impl std::error::Error for GoodManualError {}

fn main() {}
