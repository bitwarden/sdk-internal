#[bitwarden_logging::instrument(skip(password))]
fn explicit_skip_should_fail(password: &str) {
    let _ = password;
}

fn main() {}
