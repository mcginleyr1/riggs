# Development Setup

## Prerequisites

### Riggs Agent (Rust)

- Rust 1.75+ (via `rustup`)
- macOS 13+ or Linux
- Root/sudo for sensor features (Endpoint Security, eBPF)

### Murtaugh Console (Elixir)

- Elixir 1.19+ / OTP 28+ (via `mise`, `asdf`, or `brew`)
- PostgreSQL 16+
- Node.js (for esbuild/tailwind asset pipeline)

Or skip local installs entirely and use Docker.

## Quick Start — Docker (recommended)

The fastest way to get everything running:

```sh
docker compose up
```

This starts:

| Service | URL / Port | What |
|---|---|---|
| Murtaugh | http://localhost:4000 | Phoenix app with live reload |
| PostgreSQL | localhost:5432 | Meta DB + demo tenant DB |
| MinIO Console | http://localhost:9001 | S3-compatible archive storage UI |
| MinIO API | http://localhost:9000 | S3 API endpoint |

The compose file automatically:
- Creates the `murtaugh_meta` and `murtaugh_tenant_demo` databases
- Creates the `murtaugh-archive` bucket in MinIO
- Runs Ecto migrations and seeds
- Starts Phoenix with live code reload (source is mounted as a volume)

**Default login:** `admin@murtaugh.local` / `murtaugh`

MinIO credentials: `murtaugh` / `murtaugh-dev`

### Rebuilding after dependency changes

```sh
docker compose down
docker compose up --build
```

### Resetting the database

```sh
docker compose down -v   # -v removes volumes (all data)
docker compose up
```

## Quick Start — Local (no Docker)

### 1. PostgreSQL

Install and start Postgres:

```sh
# macOS
brew install postgresql@16
brew services start postgresql@16

# Create databases
createdb murtaugh_meta
createdb murtaugh_tenant_demo
```

Or if you have Postgres running already, the default `dev.exs` config
expects `postgres:postgres` on localhost:5432.

### 2. Murtaugh Console

```sh
cd murtaugh
mix deps.get
mix ecto.create
mix ecto.migrate
mix run priv/repo/seeds.exs
mix phx.server
```

Open http://localhost:4000. Login: `admin@murtaugh.local` / `murtaugh`

Assets (Tailwind + esbuild) are compiled automatically on first run.
Live reload is enabled — save a file, browser updates.

### 3. Archive Storage (optional for dev)

By default, dev uses local filesystem storage at `/tmp/murtaugh-archive`.
No setup needed.

To test with S3-compatible storage, run MinIO standalone:

```sh
docker run -p 9000:9000 -p 9001:9001 \
  -e MINIO_ROOT_USER=murtaugh \
  -e MINIO_ROOT_PASSWORD=murtaugh-dev \
  minio/minio server /data --console-address ":9001"
```

Then set env vars before starting Murtaugh:

```sh
export ARCHIVE_STORAGE=s3
export ARCHIVE_BUCKET=murtaugh-archive
export ARCHIVE_S3_ENDPOINT=http://localhost:9000
export ARCHIVE_S3_ACCESS_KEY=murtaugh
export ARCHIVE_S3_SECRET_KEY=murtaugh-dev
mix phx.server
```

### 4. Riggs Agent

```sh
cargo build --release
```

For development with the DLP module:

```sh
cargo test -p riggs-dlp       # DLP tests
cargo test -p riggs-engine     # Pipeline tests
make fmt clippy test           # What CI gates on (warnings are errors)
```

Murtaugh's checks (CI runs them against a TimescaleDB service; the tests
provision a real tenant database). `PGHOST`/`PGPORT` override the test DB
location:

```sh
cd murtaugh
mix compile --warnings-as-errors
mix format --check-formatted
mix credo
mix test
```

The agent runs as a daemon (requires root on macOS for Endpoint Security):

```sh
sudo target/release/riggs-daemon
```

CLI tool (does not need root):

```sh
target/release/riggs status
target/release/riggs dlp status
target/release/riggs dlp policy
```

## Project Layout

```
riggs/
├── Cargo.toml                 # Rust workspace root
├── crates/                    # 23 Rust crates (agent)
│   ├── riggs-daemon/          #   Daemon binary
│   ├── riggs-cli/             #   CLI binary
│   ├── riggs-dlp/             #   DLP module
│   ├── riggs-engine/          #   Detection pipeline
│   └── ...
├── murtaugh/                  # Elixir Phoenix app (console)
│   ├── lib/murtaugh/          #   Contexts + schemas
│   ├── lib/murtaugh_web/      #   LiveViews + router
│   ├── priv/repo/migrations/  #   Meta DB migrations
│   ├── priv/tenant_repo/      #   Tenant DB migrations
│   └── proto/                 #   gRPC protobuf definitions
├── extensions/                # macOS System Extension (Swift)
│   └── riggs-filter/          #   NEFilterDataProvider for DLP
├── config/                    # Agent configuration
│   ├── riggs.toml             #   Main agent config
│   ├── dlp-policy.toml        #   Default DLP policy
│   └── policies/              #   Example DLP policies
├── docker-compose.yml         # Full local dev stack
├── docker/
│   ├── Dockerfile.dev         #   Dev Dockerfile for Murtaugh
│   └── init-databases.sql     #   Postgres init script
├── notes/                     # Architecture specs
│   ├── MULTI_TENANCY.md       #   Org tree + sharding design
│   ├── DATA_MODEL.md          #   Full database schema
│   ├── GRPC_PROTOCOL.md       #   Agent↔console protocol
│   ├── LIVEVIEW_PAGES.md      #   UI page specs
│   ├── COLD_STORAGE.md        #   Archive/retention design
│   └── ARCHITECTURE_NOTES.md  #   Tech stack + process architecture
├── docs/                      # Agent design docs
├── install/                   # macOS installer scripts
└── rules/                     # Detection rules (YARA, TOML)
```

## Database Architecture

Murtaugh uses a two-tier database:

**Meta DB** (`murtaugh_meta` / `Murtaugh.Repo`):
org tree, users, permissions, tenant→shard mapping, audit log.

**Tenant DBs** (`murtaugh_tenant_<slug>` / `Murtaugh.TenantRepo` dynamic):
one per account. Agents, events, threats, DLP events — physically
separated per tenant.

In dev, both databases live on the same Postgres instance. In production,
tenant DBs can be on separate servers or regions.

### Running migrations

Meta DB (always):
```sh
cd murtaugh && mix ecto.migrate
```

Tenant DB migrations run automatically: on every boot Murtaugh provisions or
migrates each `provisioning`/`active` shard (create database, enable
TimescaleDB, migrate, apply retention) before agents connect, so new tenant
migrations roll out on deploy. An unreachable tenant is logged and skipped.

### Adding a new tenant

```sh
cd murtaugh && mix murtaugh.tenant.create "Acme Corp" acme [--retention-days 30]
```

or `Murtaugh.Tenancy.create_tenant(%{name: "Acme Corp", slug: "acme"})`. This
adds an account org node under the root, a shard for `murtaugh_tenant_acme`,
and creates and migrates that database. If provisioning fails the shard stays
`provisioning` and is finished on the next boot.

## DLP Development

### Policy hot-reload

Edit `config/dlp-policy.toml` — the agent picks up changes within seconds.
No restart needed.

### Example policies

```sh
# Start with monitoring only (no blocking)
cp config/policies/alert-only.toml config/dlp-policy.toml

# Lock down AI assistant uploads
cp config/policies/ai-lockdown.toml config/dlp-policy.toml

# Protect source code
cp config/policies/source-code-protect.toml config/dlp-policy.toml
```

### Testing the DLP pipeline

```sh
cargo test -p riggs-dlp
```

The test suite covers: file-open recording, PID correlation, domain
matching (exact + wildcard), process exclusion, stale entry eviction,
magic byte detection, and the full stage pipeline (file open → network
flow → block verdict).

## gRPC Protocol

Proto definitions are at `murtaugh/proto/riggs/v1/`. Generate code with:

```sh
cd murtaugh && make proto
```

See `murtaugh/proto/README.md` for protoc installation and details.

## Environment Variables

### Murtaugh Console

| Variable | Default | Description |
|---|---|---|
| `DATABASE_URL` | dev.exs config | Meta DB connection string |
| `SECRET_KEY_BASE` | dev.exs value | Phoenix cookie signing |
| `PORT` | 4000 | HTTP port |
| `PHX_SERVER` | unset | Set to `true` to start HTTP server |
| `PHX_HOST` | localhost | Hostname for URL generation |
| `ARCHIVE_STORAGE` | local | `s3` or `local` |
| `ARCHIVE_BUCKET` | murtaugh-archive | S3 bucket name |
| `ARCHIVE_S3_ENDPOINT` | unset | Custom S3 endpoint (MinIO, etc.) |
| `ARCHIVE_S3_REGION` | us-east-1 | S3 region |
| `ARCHIVE_S3_ACCESS_KEY` | unset | S3 access key |
| `ARCHIVE_S3_SECRET_KEY` | unset | S3 secret key |
| `ARCHIVE_LOCAL_PATH` | /tmp/murtaugh-archive | Local archive directory |
| `TENANT_DATABASE_HOST` | meta DB host | Server for new tenant DBs (unset: same server as the meta DB) |
| `TENANT_DATABASE_PORT` | 5432 | Port for new tenant DBs (when `TENANT_DATABASE_HOST` is set) |
| `TENANT_DATABASE_USER` | postgres | User for new tenant DBs (when `TENANT_DATABASE_HOST` is set) |
| `TENANT_DATABASE_PASSWORD` | postgres | Password for new tenant DBs (when `TENANT_DATABASE_HOST` is set) |

### Riggs Agent

| Variable | Default | Description |
|---|---|---|
| `RIGGS_SOCKET` | /var/run/riggs.sock | IPC socket path |
| `RIGGS_CONFIG` | /etc/riggs/riggs.toml | Config file path |
