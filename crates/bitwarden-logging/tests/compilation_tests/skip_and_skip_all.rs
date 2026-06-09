#[bitwarden_logging::instrument(skip(password), skip_all)]
fn both_should_fail(password: &str) {
    let _ = password;
}

fn main() {}
