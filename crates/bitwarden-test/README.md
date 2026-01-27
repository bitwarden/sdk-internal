# Bitwarden Test

<div class="warning">
This crate should only be used in tests and should not be included in production builds.
</div>

Contains test utilities for Bitwarden.

## Play Framework

The Play framework provides scene-based E2E testing with automatic test isolation and cleanup. Using
the server side `SeederApi` to generate data.

### How It Works

1. Each `Play` instance generates a unique `play_id` (UUID)
2. All HTTP requests include an `x-play-id` header for server-side test isolation
3. Any db entry created through a request associated with an `x-play-id` (users, etc.) are saved as
   associated with that `play_id`
4. When the `Play` instance is dropped, associated data is automatically cleaned up

### Usage

```rust
use bitwarden_test::play::{Play, SingleUserArgs, SingleUserScene};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn test_example() {
    // Create a Play instance - generates unique play_id
    let play = Play::new();

    // Create a test user via the seeder API
    let args = SingleUserArgs {
        email: "test@example.com".to_string(),
        verified: true,
        ..Default::default()
    };
    let scene = play.scene::<SingleUserScene>(&args).await.unwrap();

    let email = scene.get_mangled("test@example.com");

    // Use credentials for testing...

    // Cleanup happens automatically when `play` is dropped
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
