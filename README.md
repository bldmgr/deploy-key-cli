# deploy-key-cli

Create deploy keys using GitHub OAuth with automatically generated 4096-bit RSA key pair

## Features

- ✅ Generates 4096-bit RSA SSH key pair
- ✅ Creates GitHub deploy key via OAuth
- ✅ **Supports both read-only and read-write access**
- ✅ Automatically updates `~/.ssh/config` with host entry
- ✅ Saves private key with proper permissions (600)

## Setup

Create a GitHub OAuth App and set "Authorization callback URL" to http://localhost:8080/callback (or your custom port)

## Usage

### Create Deploy Key with Write Access (default)

```cmd
go build -o github-deploy-key .

./github-deploy-key \
  -client-id=your_client_id \
  -client-secret=your_client_secret \
  -repo=owner/repository \
  -title="Production Deploy Key"
```

Or explicitly enable write access:
```cmd
./github-deploy-key \
  -client-id=your_client_id \
  -client-secret=your_client_secret \
  -repo=owner/repository \
  -title="Production Deploy Key" \
  -write
```

### Create Read-Only Deploy Key

```cmd
./github-deploy-key \
  -client-id=your_client_id \
  -client-secret=your_client_secret \
  -repo=owner/repository \
  -title="CI Read-Only Key" \
  -read-only
```

## What It Does

This will:
1. Generate a new SSH key pair
2. Create a deploy key on GitHub (with write or read-only access)
3. Save the private key to `<title>_deploy_key`
4. Automatically append an entry to `~/.ssh/config`:

```
Host github.com-<repository>
  Hostname github.com
  User bldmgr
  IdentityFile=/path/to/<title>_deploy_key
  IdentitiesOnly yes
```

## Test

Use the host alias from SSH config to clone:
```
git clone git@github.com-repository:owner/repository.git
```

Or add to your CI/CD configuration:
```
ssh-add <title>_deploy_key
git clone git@github.com-repository:owner/repository.git
```

## Access Types

- **Read-Write (default)**: Deploy key can push and pull from the repository
- **Read-Only**: Deploy key can only pull from the repository (use `-read-only` flag)
