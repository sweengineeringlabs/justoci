# Registry credential providers

`ocimage publish` and `ocimage verify <registry-ref>` resolve
credentials through a chain of [`CredentialProvider`] impls. The
operator-facing surface is the `--auth` flag plus a small set of
companion flags / environment variables. This page documents each
provider, what build profile activates it, and what fields it
expects.

## Selection matrix

| `--auth <mode>` | Companion flags / env             | Cargo feature flag | Use case                                            |
| --------------- | --------------------------------- | ------------------ | --------------------------------------------------- |
| `env` (default) | `REGISTRY_TOKEN`, `REGISTRY_USERNAME`+`REGISTRY_PASSWORD` | (none)             | CI runners with creds already in the env             |
| `basic`         | `--registry-username`, `--registry-password` | (none)        | Operator-supplied basic auth                         |
| `bearer`        | `--registry-token`                | (none)             | Pre-acquired PAT (e.g. GitHub Actions GH_PAT)        |
| `vault`         | `VAULT_ADDR`, `VAULT_TOKEN`, `--vault-base-path` | `vault`     | Vault-managed credentials (KV v2)                    |
| `docker-config` | `--docker-config-path`            | `docker-config`    | Reuse `~/.docker/config.json` from `docker login`    |
| (`--no-auth`)   | —                                 | (none)             | Explicit anonymous; for public-readable registries   |

## How the chain walks

An operator picks **one** of `--auth env|basic|bearer|vault` (or
`--no-auth`). The provider that mode names is the one that runs.
The 401-then-`WWW-Authenticate` bearer-token dance (OCI Distribution
§3.4) runs on top of every mode — public Docker Hub / GHCR repos
work without any operator-supplied credentials because the registry
issues the bearer mid-call.

When a provider produces credentials, the wire layer attaches the
`Authorization` header and continues. When a provider is **broken**
(Vault is down, env vars are set-but-empty, …) the failure is
surfaced as a typed `CliError::Cli` (exit code 64) — the chain does
**not** silently fall through to anonymous, because an operator who
configured Vault wants to know it failed, not to find their CI
silently pushed unauthenticated.

## `env`

Reads, in order:

1. `REGISTRY_TOKEN` — preferred. If set + non-empty, used as a
   bearer token verbatim.
2. `REGISTRY_USERNAME` + `REGISTRY_PASSWORD` — used as Basic auth.
   Both must be non-empty.

Either env var being set-but-empty is a typed error (not a "fall
through"). An operator who exported the variable wanted to use it;
surfacing the misconfiguration beats a silent anonymous push.

## `basic`

Requires both `--registry-username` (or `REGISTRY_USERNAME`) and
`--registry-password` (or `REGISTRY_PASSWORD`). Both must be
non-empty. Sends `Authorization: Basic <base64(user:pass)>`. Use
over HTTPS only — registries don't enforce TLS for Basic.

## `bearer`

Requires `--registry-token` (or `REGISTRY_TOKEN`). Sends
`Authorization: Bearer <token>` verbatim. Use for pre-acquired
PATs / OIDC-issued tokens.

## `vault` (Cargo feature `vault`)

Pulls the registry credentials from a HashiCorp Vault KV v2 path.
**Only available when the CLI is built with `cargo build --features vault`**;
the default `ocimage` binary doesn't pull the `vaultrs` /
`tokio` deps and rejects `--auth vault` at parse time with a
specific "rebuild with `--features vault`" error.

### Auth to Vault

By default, the provider reads `VAULT_ADDR` and `VAULT_TOKEN` from
the process environment — the standard Vault SDK convention. A CI
runner that already has Vault Agent populating those vars works
without per-tool config.

For AppRole / Kubernetes / JWT auth, callers can pre-acquire a
Vault token by external means (e.g. `vault login -method=approle`)
and export it as `VAULT_TOKEN` for `ocimage` to consume. AppRole
login from inside `ocimage` itself is a follow-up.

### Path layout

The provider reads `<base_path>/<registry>` (KV v2 convention).
Default `--vault-base-path` is `secret/data/registry` — splitting
to mount `secret` + prefix `registry`. So:

```
ocimage verify ghcr.io/acme/img:v1 --auth vault
```

reads `secret/data/registry/ghcr.io` on the wire.

### Secret schema

The KV v2 secret under `<base_path>/<registry>` is expected to be a
JSON object carrying either:

```json
{ "username": "ci-user", "password": "ci-secret" }
```

(maps to `Authorization: Basic <b64>`) or:

```json
{ "token": "ghp_xxxxxxxxxxxx" }
```

(maps to `Authorization: Bearer <token>`).

If both `token` AND (`username`+`password`) are present, **token
wins**. Tokens are usually narrower-scoped (registry-specific PATs)
and more recently rotated than long-lived admin userpass pairs.

A schema mismatch (neither shape recognisable, fields of wrong
type, fields set-but-empty) surfaces as a hard `--auth vault`
error rather than a silent fall-through.

### Failure mapping

| Vault response          | Provider outcome                       | Operator-facing meaning                               |
| ----------------------- | -------------------------------------- | ----------------------------------------------------- |
| 200 + valid schema      | `Ok(Some(creds))`                      | Works.                                                |
| 200 + malformed schema  | `Err(ProviderFailed)`                  | Schema bug — fix the secret payload.                  |
| 404 (path not found)    | `Ok(None)` — chain falls through       | No Vault entry for this registry; chain hits next.    |
| 401 / 403               | `Err(ProviderFailed)`                  | Vault auth is broken — fix the token / policy.        |
| Network failure         | `Err(ProviderFailed)`                  | Vault unreachable — fix the network / `VAULT_ADDR`.   |

### Worked example (CI runner with Vault Agent)

The operator's CI box runs Vault Agent, which writes a short-lived
token into `${VAULT_TOKEN_FILE}`. The CI workflow does:

```bash
export VAULT_ADDR=https://vault.internal:8200
export VAULT_TOKEN="$(cat $VAULT_TOKEN_FILE)"

# Build ocimage with the vault feature on.
cargo install --path cli --features vault

# Push an artifact, with Vault providing the registry creds.
ocimage publish ./build/out \
    --to registry:ghcr.io/acme/img:0.1.0 \
    --auth vault \
    --vault-base-path secret/data/registry
```

Behind the scenes: `ocimage` calls `VaultClient::new(VAULT_ADDR, VAULT_TOKEN)`,
reads `secret/data/registry/ghcr.io`, finds
`{ "token": "ghp_..." }`, and the publish path sees
`RegistryAuth::Bearer { token }` — same wire shape as
`--auth bearer --registry-token ghp_...` would have produced, but
the operator never had the GHCR token in the local env or on the
command line.

## `docker-config` (Cargo feature `docker-config`)

Reads registry credentials from the static `~/.docker/config.json`
file an operator already wrote when they ran `docker login`.
**Only available when the CLI is built with `cargo build --features docker-config`**;
the default `ocimage` binary doesn't pull the `base64` / `dirs`
deps and rejects `--auth docker-config` at parse time with a
specific "rebuild with `--features docker-config`" error.

### What this provider IS NOT

This provider does **not** depend on Docker the daemon being
installed, running, or even ever invoked locally. It only reads the
static JSON file at the well-known path. That keeps the
"no Docker as a runtime dep" rule from
[`docs/3-design/scope-and-boundaries.md`](../3-design/scope-and-boundaries.md)
intact: an operator with a `config.json` (e.g. one written by
`podman login`, or synthesised by a CI workflow's
`mkdir ~/.docker && cat > config.json` step) gets credential
resolution without `docker` itself being on PATH.

### Path resolution

Default path is `~/.docker/config.json`, resolved via the `dirs`
crate so it works portably on Windows (`%USERPROFILE%\.docker`),
Linux (`$HOME/.docker`), and macOS without per-platform cfg blocks.

The default can be overridden with `--docker-config-path PATH`
(useful for CI runners that stage the file in a non-default
location, or for operators who keep multiple per-environment
config files).

### Schema

The config file is the standard Docker config v2 form:

```json
{
  "auths": {
    "ghcr.io": { "auth": "<base64-encoded username:password>" },
    "registry.acme.io": {
      "username": "...",
      "password": "..."
    },
    "tokenized.example": {
      "identitytoken": "<oauth-style-bearer>"
    }
  },
  "credHelpers": {
    "ecr.amazonaws.com": "ecr-login"
  }
}
```

v0 of this provider supports the `auths` block only. The
`credHelpers` delegation requires a subprocess call to a
`docker-credential-<name>` binary (stdin: registry URL, stdout:
`{"Username":"...","Secret":"..."}` JSON) and is tracked as a
v0.2 follow-up issue.

### Lookup rules

1. Look up `auths.<registry>` exactly. If found and parseable,
   return it.
2. If not found, try `auths.https://<registry>` — Docker stores
   some entries with the scheme prefix (older client versions,
   explicit `docker login https://ghcr.io`).
3. If still not found, return `Ok(None)` so the chain walker
   moves to the next provider.

### Precedence: `auth` field vs explicit `username` / `password`

When both are present in the same entry, **the `auth` field wins**.
Docker's documented behaviour is that `auth` is the authoritative
base64-encoded form; explicit `username` / `password` fields are a
convenience shape some tools (and older `docker login` versions)
emit. Reversing the precedence would mean two tools editing the
same `config.json` would disagree on which credentials are active
depending on which one wrote last.

If `identitytoken` is set and non-empty, it maps to a Bearer
flavour of resolved auth; otherwise the entry maps to Basic.

### Failure mapping

| Config state                                 | Provider outcome              | Operator-facing meaning                                       |
| -------------------------------------------- | ----------------------------- | ------------------------------------------------------------- |
| File does not exist                          | `Ok(None)` — chain falls through | Operator never ran `docker login`; chain hits next provider. |
| File exists, no entry for this registry      | `Ok(None)` — chain falls through | Not logged into this registry; chain hits next provider.     |
| File exists, valid entry                     | `Ok(Some(creds))`             | Works.                                                        |
| File exists but is malformed JSON            | `Err(ProviderFailed)`         | Schema corruption — fix the config file.                     |
| `auth` field is not valid base64             | `Err(ProviderFailed)`         | Data corruption — fix the `auth` field.                      |
| `auth` field decodes but lacks `:` separator | `Err(ProviderFailed)`         | Schema bug — `auth` must encode `username:password`.         |
| Half-populated entry (e.g. user, no pass)    | `Err(ProviderFailed)`         | Schema bug — fix the entry.                                  |
| I/O fault reading the file                   | `Err(Io)`                     | Permission or media error — fix file ACLs.                   |

### Worked example (CI runner that already ran `docker login`)

The CI workflow logs into the registry once, then drives `ocimage`
without re-supplying credentials:

```bash
# Install ocimage with the docker-config feature on.
cargo install --path cli --features docker-config

# Existing CI step writes ~/.docker/config.json:
echo "$GHCR_PAT" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

# ocimage reuses the credential without re-receiving it on the CLI:
ocimage publish ./build/out \
    --to registry:ghcr.io/acme/img:0.1.0 \
    --auth docker-config
```

Behind the scenes: `ocimage` reads `~/.docker/config.json`, finds
`auths."ghcr.io"`, decodes the `auth` field, and the publish path
sees `RegistryAuth::Basic { username, password }` — same wire
shape `--auth basic --registry-username ... --registry-password ...`
would have produced, but the secret never appeared on the CLI
or in the workflow YAML.

For an operator who keeps a non-default config file (e.g. a
per-project copy under `./.docker/config.json`):

```bash
ocimage verify ghcr.io/acme/img:v1 \
    --auth docker-config \
    --docker-config-path ./.docker/config.json
```

## Setting up a local Vault dev server (testing only)

```bash
vault server -dev -dev-root-token-id=dev-only &
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_TOKEN=dev-only

# Provision a registry credential.
vault kv put secret/registry/ghcr.io \
    username=ci-user password=ci-secret

# Run ocimage with the vault feature on.
cargo run --features vault -p swe_justoci_oci_cli -- \
    verify ghcr.io/acme/img:v1 --auth vault
```

The `ocimage` integration test that exercises this end-to-end is
`cli/tests/vault_provider_test.rs`, gated `#[ignore]` so a
default `cargo test` skips it. CI without Vault produces no
spurious failure; running it locally requires the `vault` binary
on PATH and the env vars above.

## Relationship to `--no-auth`

`--no-auth` is the explicit-anonymous override and is mutually
exclusive with every `--auth ...` mode. It skips credential
resolution entirely; the wire layer sends no `Authorization:`
header and the registry decides whether anonymous access is
allowed.

Use `--no-auth` for:
- Local `registry:2` smoke tests (no auth configured).
- Public-writable mirrors (none come to mind, but the option is
  there).

For public-readable registries, prefer the default `--auth env`
without setting any of the `REGISTRY_*` env vars — the provider
chain will return `None`, the wire layer will go anonymous, and
the 401 dance will up-grade to bearer if the registry requires it.
