# bitwarden-server-communication-config

Server communication configuration management for the Bitwarden SDK.

## Overview

This crate provides storage and client abstractions for managing _external_ (not `bitwarden/server`)
server communication settings, particularly for environments that require load balancer session
affinity through SSO cookie authentication.

In self-hosted deployments with load balancers that perform SSO authentication, Browser and Web
clients naturally inherit cookies from the browser's cookie store. However, Desktop and Mobile
clients require explicit cookie management to maintain session affinity across requests.

## Relationship to Environment Configuration

This crate manages **connection-level** configuration (per-hostname cookie requirements), which is
distinct from `bitwarden-core`s **environment-level** configuration (what are my server urls). These
names may be easily confused but serve separate purposes. Chances are if you're reading this you're
looking for `client_settings.rs` or similar 🙂

## Architecture

The crate follows the architecture pattern of other foundation layer SDK exports:

- **`ServerCommunicationConfig`**: Data structures for bootstrap configuration and SSO cookie
  settings
- **`ServerCommunicationConfigRepository`**: Storage abstraction trait for WASM interop with
  TypeScript
- **`ServerCommunicationConfigClient`**: High-level client for retrieving configuration and cookies
  by hostname

### Data Model

Configuration is stored per-hostname and supports two bootstrap modes:

1. **Direct**: Standard direct connection (no special cookies required)
2. **SSO Cookie Vendor**: Load balancer requires SSO authentication cookies for session affinity

## Usage

The SDK client is instantiated by TypeScript with a State Provider-backed repository:

```typescript
import { ServerCommunicationConfigClient } from "@bitwarden/sdk-internal";

// State Provider provides the repository implementation
const repository = stateProvider.getGlobal(ServerCommunicationConfig);
const client = new ServerCommunicationConfigClient(repository);

// Check if bootstrap is needed
await client.needsBootstrap("vault.example.com");

// Get cookies for HTTP requests
await client.cookies("vault.example.com");
```

## Features

- `wasm`: Enables WebAssembly bindings for TypeScript integration

## Non-Goals

- General-purpose cookie jar implementation (only manages specific SSO cookies)
- Environment management (handled by environment configuration)
