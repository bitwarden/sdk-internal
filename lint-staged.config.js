export default {
  "*": "prettier --cache --ignore-unknown --write",
  "*.rs": (stagedFiles) => [
    "cargo +nightly fmt",
    "cargo dylint --all -- --all-features --all-targets",
  ],
  "Cargo.toml": (stagedFiles) => [
    "cargo +nightly fmt",
    "cargo +nightly udeps --workspace --all-features",
    "cargo sort --workspace",
  ],
};
