export default {
  "*": "prettier --cache --ignore-unknown --write",
  "*.rs": (stagedFiles) => [
    "bash scripts/lint.sh --fix --only fmt",
    "bash scripts/lint.sh --only clippy",
    "bash scripts/lint.sh --only dylint",
  ],
  "Cargo.toml": (stagedFiles) => [
    "bash scripts/lint.sh --fix --only fmt",
    "bash scripts/lint.sh --only udeps",
    "bash scripts/lint.sh --fix --only sort",
  ],
};
