# Bitwarden CLI (testing)

A testing CLI for the Bitwarden Password Manager SDK.

## Authentication

### Login with API Key

```bash
# With environment variables
export BW_CLIENTID="user.xxx"
export BW_CLIENTSECRET="xxx"
export BW_PASSWORD="xxx"
bw login api-key

# Or with interactive prompts
bw login api-key
```

The login command returns a session key that can be used for subsequent commands.

### Using Sessions

```bash
# Save session to environment variable
export BW_SESSION="<session-key-from-login>"

# Or pass directly to commands
bw list items --session "<session-key>"
```

## Commands

### List Items

```bash
# List all items
bw list items

# Search items
bw list items --search "github"

# Filter by folder, collection, or organization
bw list items --folderid "<folder-id>"
bw list items --collectionid "<collection-id>"
bw list items --organizationid "<org-id>"

# Show deleted items
bw list items --trash
```
