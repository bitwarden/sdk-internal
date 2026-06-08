#[bitwarden_logging::instrument(skip_all)]
fn explicit_skip_all_should_fail(password: &str) {
    let _ = password;
}

fn main() {}
