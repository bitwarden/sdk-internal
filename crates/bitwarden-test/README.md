---
category: core
---

# Bitwarden Test

Test utilities such as mock implementations and helpers for testing repositories and testing non
mockable API bindings (outside of bitwarden-api crates).

<div class="warning">
This crate should only be used in tests and should not be included in production builds.
</div>

## Play Framework

The Play framework provides scene-based E2E testing with automatic test isolation and cleanup. Using
the server side `SeederApi` to generate data.

### How It Works

1. Each `Play` instance generates a unique `play_id` (UUID)
2. All HTTP requests include an `x-play-id` header for server-side test isolation
3. Any db entry created through a request associated with an `x-play-id` (users, etc.) are saved as
   associated with that `play_id`
4. When the test closure completes, associated data is automatically cleaned up

### Usage

Use the `#[play_test]` macro for the most ergonomic experience:

```rust
use bitwarden_test::play::{play_test, Play, SingleUserArgs, SingleUserScene};

#[play_test]
async fn test_example(play: Play) {
    // Create a test user via the seeder API
    let args = SingleUserArgs {
        email: "test@example.com".to_string(),
        verified: true,
        ..Default::default()
    };
    let scene = play.scene::<SingleUserScene>(&args).await.unwrap();

    // Access user data from the scene result
    let user_id = &scene.result().user_id;
    let api_key = &scene.result().api_key;

    // Use mangled values for test isolation
    let email = scene.get_mangled("test@example.com");

    // Use credentials for testing...

    // Cleanup happens automatically when the test completes
}
```

Or use the builder pattern directly for more control:

```rust
use bitwarden_test::play::{Play, PlayConfig, SingleUserArgs, SingleUserScene};

#[tokio::test]
async fn test_example() {
    Play::builder()
        .config(PlayConfig::new("https://api", "https://identity", "http://seeder"))
        .run(|play| async move {
            let args = SingleUserArgs {
                email: "test@example.com".to_string(),
                verified: true,
                ..Default::default()
            };
            let scene = play.scene::<SingleUserScene>(&args).await.unwrap();

            // Use credentials for testing...
        })
        .await;
}
```

### Environment Variables

| Variable                 | Default                           | Description         |
| ------------------------ | --------------------------------- | ------------------- |
| `BITWARDEN_API_URL`      | `https://localhost:8080/api`      | Base API URL        |
| `BITWARDEN_IDENTITY_URL` | `https://localhost:8080/identity` | Identity server URL |
| `BITWARDEN_SEEDER_URL`   | `http://localhost:5047`           | Seeder API URL      |

### Running E2E Tests

E2E tests require a running Bitwarden server with the seeder API enabled:

```bash
cargo test -p bw --features integration
```
