---
applyTo: "**/*.rs"
---

# Project coding standards for Rust

## Formatting and Linting

- Use `cargo +nightly fmt` to format code
- Use `cargo clippy` to lint code and catch common mistakes
- All code must be formatted and linted before being committed

## Error Handling

### Avoid Panics

- **Never use `unwrap()`** - `clippy` will forbid this
- **Use `expect()` sparingly** - always provide a helpful message
- **Prefer `?` operator** for error propagation

```rust
// ❌ DON'T: Use unwrap or expect without context
let value = result.unwrap();

// ✅ DO: Use ? for error propagation
let value = result?;

// ✅ DO: Use expect with a helpful message
let value = result.expect("Config is validated at startup, this should never fail");
```

### Result and Option Handling

Avoid using `match` for simple cases. Use the below methods if it makes the code cleaner.

```rust
// Use ? for error propagation
do_something().map_err(|e| "Another error")?

// Use if let for single arm matches
if let Ok(value) = result {
    outer.append(value);
}

// Use Option methods
some_option.map(|x| x + 1)
some_option.and_then(|x| func(x + 1))
some_option.unwrap_or(1)
some_option.ok_or("error")

// Use Result methods
result.map_err(|_| "Another error")
```

## Naming Conventions

- Use `snake_case` for functions, variables, and modules
- Use `PascalCase` for types, traits, and enum variants
- Use `SCREAMING_SNAKE_CASE` for constants
- Use descriptive names and avoid abbreviations

## Documentation

- All public APIs must have doc comments using `///`
- Include examples for complex functions
- Use `//` for internal comments that explain "why", not "what"

## Memory Management

- Use references (`&`) instead of owned values when possible
- Use `&str` for string parameters when you don't need ownership
- Use `String` for owned strings and return values
- Pre-allocate collections with known sizes: `Vec::with_capacity()`

## Error Types

- Define domain-specific error types
- Use `thiserror` crate for error derivation

## Testing

- Place unit tests in the same file using `#[cfg(test)]`
- Use descriptive test names that describe the scenario
- Follow the Arrange-Act-Assert pattern

## Security

- Always validate input parameters
- Use constant-time operations for cryptographic comparisons

## Additional Guidelines

- Keep functions focused and single-purpose
- Group imports: std library, external crates, local modules
- Mark functions as `async` only when they perform async operations
