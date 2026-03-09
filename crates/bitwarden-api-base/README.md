# bitwarden-api-base

Base types and utilities for Bitwarden API clients.

## Overview

This crate provides common functionality shared across all Bitwarden API client crates:

- `Configuration` - HTTP client configuration with authentication options
- `Error` - Error type for API operations
- `ResponseContent` - Container for error response data
- `urlencode` - URL encoding utility
- `parse_deep_object` - Deep object query parameter serialization
- `ContentType` - Content type parsing

## Usage

This is an internal crate and should not be used directly. It is re-exported by the API client
crates:

- `bitwarden-api-api`
- `bitwarden-api-identity`
