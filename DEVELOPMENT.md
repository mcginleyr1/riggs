# Development Setup

## Prerequisites

### Riggs Agent (Rust)

- Rust via `rustup`. The toolchain is pinned in `rust-toolchain.toml`, and
  rustup installs it on the first `cargo` run in the repo.
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

### 5. Browser extension (phishing protection)

The extension is plain JavaScript with no build step; `package.json` holds only
its test and lint tooling (Node's built-in test runner, jsdom, Biome). Install
the tooling once, then:

```sh
npm --prefix extensions/riggs-browser ci
npm --prefix extensions/riggs-browser test      # node --test over test/**/*.test.js
npm --prefix extensions/riggs-browser run lint  # biome check ext test
```

CI runs both on Node 25, the version this was developed with. Every test runs
in Node against stand-ins for the browser's interfaces (jsdom and a fake
`chrome` object); nothing runs in a real browser. `docs/PHISHING.md` holds the
contract between the extension's files, the native-messaging host and the
daemon, and lists what is unverified.

#### A development daemon with phishing protection, as an unprivileged user

An ordinary user can run the daemon (the macOS sensor started without root in
the one run this was tried). It reads `/etc/riggs/riggs.toml`, and failing
that `config/riggs.toml` relative to its working directory. Its default paths
(`/var/lib/riggs`, `/var/run/riggs.sock`) are not writable by you, so run it in
a scratch directory with its own `config/`:

```sh
mkdir -p /tmp/riggs-dev/config
cp config/riggs.toml config/phishing-policy.toml /tmp/riggs-dev/config/
```

Keep the directory path short: a Unix socket path is limited to 104 bytes on
macOS. In `/tmp/riggs-dev/config/riggs.toml`, point every path at that
directory: `[store] db_path`, `[comms] socket_path` and `filter_socket_path`,
`[response] quarantine_path`, `pf_conf_path` and `snapshot_path`, and `[intel]
cache_path`. To keep the daemon from doing anything else, as the run that
tested this did, also switch off `[engine] static_ai_enabled`,
`behavioral_ai_enabled` and `rules_enabled`, `[intel] enabled` and the
`*_enabled` switches under `[intel.feeds]`, `[dlp] enabled`, and `[response] auto_respond`, `kill_on_critical`,
`quarantine_on_malicious` and `preemptive_snapshots`. Then:

```sh
cargo build -p riggs-daemon -p riggs-cli
cd /tmp/riggs-dev && /path/to/riggs/target/debug/riggs-daemon
```

The daemon finds `config/phishing-policy.toml` in the same directory and logs
`phishing protection initialized`, with the mode. In another shell, use the
CLI with `--socket` (it goes before the command). Because you run the daemon,
you are its owner: the owner-only commands need no `sudo`.

```sh
target/debug/riggs --socket /tmp/riggs-dev/riggs.sock phishing status
target/debug/riggs --socket /tmp/riggs-dev/riggs.sock phishing mode warn
target/debug/riggs --socket /tmp/riggs-dev/riggs.sock phishing recent
```

To put a browser in front of it: load `extensions/riggs-browser/ext` unpacked
at `chrome://extensions` (its manifest `key` gives it the ID the host manifest
allows), and register a host manifest for your own user, a copy of
`install/native-messaging/com.riggs.browser.json` with `path` set to the
absolute path of `target/debug/riggs-browser-host`, in
`~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` on macOS
or `~/.config/google-chrome/NativeMessagingHosts/` on Linux (Chrome's
documented per-user directories). The host reads `RIGGS_SOCKET` for the socket,
so start the browser from a shell in which it is exported. That Chrome passes
its environment on to the host, and which of two manifests wins when the
installer's system-wide one also exists, are both unverified. The daemon
rereads the policy file when it changes, so editing the mode in
`/tmp/riggs-dev/config/phishing-policy.toml` takes effect without a restart.

## Project Layout

```
riggs/
├── Cargo.toml                 # Rust workspace root
├── crates/                    # 26 Rust crates (agent)
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
├── extensions/
│   ├── riggs-filter/          #   macOS System Extension (Swift): NEFilterDataProvider (egress + DLP), host app, build.sh
│   └── riggs-browser/         #   Chromium extension for phishing protection (JavaScript): ext/ is what a browser loads
├── config/                    # Agent configuration
│   ├── riggs.toml             #   Main agent config
│   ├── phishing-policy.toml   #   Phishing policy (mode, thresholds, weights, phrases)
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
├── install/                   # macOS installer scripts, launchd plists, native-messaging host manifest
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
| `RIGGS_SOCKET` | /var/run/riggs.sock | IPC socket path for the clients: `riggs` (the `--socket` option overrides it), the menubar app and `riggs-browser-host`. The daemon takes its socket from `[comms] socket_path` |

The daemon has no variable for the config file: it reads `/etc/riggs/riggs.toml`,
and failing that `config/riggs.toml` relative to its working directory. It finds
`phishing-policy.toml` the same way.
