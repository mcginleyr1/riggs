# Murtaugh — Cold Storage & Data Lifecycle

## Problem

Events, threats, DLP events, and device events are time-partitioned with
a retention window (default 90 days). When partitions age out, the data
is dropped. But customers need that data for:

- Compliance (keep 1-7 years depending on regulation)
- Forensic investigation months after an incident
- Trend analysis across long time horizons
- Legal hold / e-discovery

We need to archive partitions to object storage before dropping them,
and provide a way to query or restore archived data.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Tenant DB                             │
│                                                          │
│  events_2026_01  events_2026_02  events_2026_03 (live)  │
│       │                │                                 │
│       │ retention      │ retention                       │
│       │ expired        │ expired                         │
│       ▼                ▼                                 │
│  ┌──────────────────────────┐                            │
│  │   Oban: PartitionReaper  │                            │
│  │                          │                            │
│  │  1. Export to Parquet    │                            │
│  │  2. Upload to bucket    │                            │
│  │  3. Record in manifest  │                            │
│  │  4. DROP partition       │                            │
│  └────────────┬─────────────┘                            │
└───────────────│──────────────────────────────────────────┘
                │
                ▼
┌───────────────────────────────────────────────┐
│           Object Storage (cloud-agnostic)      │
│                                                │
│  s3://murtaugh-archive/                        │
│  ├── tenant-acme/                              │
│  │   ├── events/                               │
│  │   │   ├── 2026-01.parquet                   │
│  │   │   ├── 2026-02.parquet                   │
│  │   │   └── manifest.json                     │
│  │   ├── threats/                              │
│  │   │   ├── 2026-01.parquet                   │
│  │   │   └── manifest.json                     │
│  │   ├── dlp_events/                           │
│  │   │   └── ...                               │
│  │   └── device_events/                        │
│  │       └── ...                               │
│  └── tenant-globex/                            │
│      └── ...                                   │
└───────────────────────────────────────────────┘
```

## Cloud-Agnostic Object Storage

We use a single abstraction that supports S3, GCS, Azure Blob, and
local filesystem (for dev/self-hosted). The Elixir ecosystem has
good options:

### Storage Abstraction

```elixir
defmodule Murtaugh.Archive.Storage do
  @moduledoc """
  Cloud-agnostic object storage interface.
  Backed by ExAws (S3/GCS) or Azure Blob client.
  """

  @callback put(bucket :: String.t(), key :: String.t(), body :: binary(), opts :: keyword()) ::
              :ok | {:error, term()}

  @callback get(bucket :: String.t(), key :: String.t()) ::
              {:ok, binary()} | {:error, term()}

  @callback list(bucket :: String.t(), prefix :: String.t()) ::
              {:ok, [String.t()]} | {:error, term()}

  @callback delete(bucket :: String.t(), key :: String.t()) ::
              :ok | {:error, term()}

  @callback presigned_url(bucket :: String.t(), key :: String.t(), expires_in :: integer()) ::
              {:ok, String.t()} | {:error, term()}
end
```

### Backend Implementations

```elixir
# S3-compatible (AWS S3, MinIO, Ceph, DigitalOcean Spaces, Backblaze B2)
defmodule Murtaugh.Archive.Storage.S3 do
  @behaviour Murtaugh.Archive.Storage
  # Uses ex_aws + ex_aws_s3
  # Supports any S3-compatible endpoint via config
end

# Google Cloud Storage
defmodule Murtaugh.Archive.Storage.GCS do
  @behaviour Murtaugh.Archive.Storage
  # Uses goth + google_api_storage
  # GCS has an S3-compatible XML API — can also just use the S3 backend
  # with the GCS interop endpoint
end

# Azure Blob Storage
defmodule Murtaugh.Archive.Storage.Azure do
  @behaviour Murtaugh.Archive.Storage
  # Uses azure_storage
end

# Local filesystem (dev / air-gapped deployments)
defmodule Murtaugh.Archive.Storage.Local do
  @behaviour Murtaugh.Archive.Storage
  # Writes to a local directory, e.g., /var/lib/murtaugh/archive/
end
```

### Configuration

```elixir
# config/runtime.exs

config :murtaugh, Murtaugh.Archive,
  storage: System.get_env("ARCHIVE_STORAGE", "s3"),  # s3, gcs, azure, local
  bucket: System.get_env("ARCHIVE_BUCKET", "murtaugh-archive"),

  # S3 / S3-compatible
  s3_endpoint: System.get_env("ARCHIVE_S3_ENDPOINT"),     # nil = AWS, or MinIO URL
  s3_region: System.get_env("ARCHIVE_S3_REGION", "us-east-1"),
  s3_access_key: System.get_env("ARCHIVE_S3_ACCESS_KEY"),
  s3_secret_key: System.get_env("ARCHIVE_S3_SECRET_KEY"),

  # GCS
  gcs_project: System.get_env("ARCHIVE_GCS_PROJECT"),
  gcs_credentials: System.get_env("GOOGLE_APPLICATION_CREDENTIALS"),

  # Azure
  azure_account: System.get_env("ARCHIVE_AZURE_ACCOUNT"),
  azure_key: System.get_env("ARCHIVE_AZURE_KEY"),
  azure_container: System.get_env("ARCHIVE_AZURE_CONTAINER"),

  # Local
  local_path: System.get_env("ARCHIVE_LOCAL_PATH", "/var/lib/murtaugh/archive")
```

For most deployments, S3-compatible covers everything — MinIO for
self-hosted, and the S3 API is supported by GCS (via interop) and
most object stores.

## Export Format: Parquet

Parquet is the right choice for archived telemetry:
- Columnar: efficient for analytical queries (scan only needed columns)
- Compressed: typically 5-10x smaller than JSON/CSV
- Widely supported: every data tool reads Parquet (DuckDB, Spark, Pandas,
  BigQuery, Athena, Snowflake)
- Schema-preserving: types are retained, not lost like CSV

We use the `explorer` Elixir library (backed by Rust Polars) for Parquet
serialization:

```elixir
# mix.exs
{:explorer, "~> 0.10"}
```

### Export Process

```elixir
defmodule Murtaugh.Archive.Exporter do
  @doc """
  Exports a table partition to Parquet and uploads to object storage.
  """
  def export_partition(tenant_shard, table, partition_name, year_month) do
    repo = ShardManager.get_repo!(tenant_shard.id)
    TenantRepo.put_dynamic_repo(repo)

    # Stream rows from the partition to avoid loading everything in memory
    query = "SELECT * FROM #{partition_name} ORDER BY timestamp"

    {:ok, dataframe} =
      TenantRepo.query(query)
      |> rows_to_dataframe(table)

    # Write to temp Parquet file
    tmp_path = Path.join(System.tmp_dir!(), "#{partition_name}.parquet")
    Explorer.DataFrame.to_parquet(dataframe, tmp_path)

    # Upload to object storage
    key = archive_key(tenant_shard, table, year_month)
    body = File.read!(tmp_path)
    storage().put(bucket(), key, body, content_type: "application/octet-stream")

    # Record in manifest
    file_size = byte_size(body)
    row_count = Explorer.DataFrame.n_rows(dataframe)
    update_manifest(tenant_shard, table, year_month, key, file_size, row_count)

    # Clean up temp file
    File.rm(tmp_path)

    {:ok, %{key: key, size: file_size, rows: row_count}}
  end

  defp archive_key(shard, table, year_month) do
    "#{shard.name}/#{table}/#{year_month}.parquet"
  end
end
```

## Data Lifecycle: The Reaper

An Oban worker runs daily per tenant and manages the full lifecycle:

```elixir
defmodule Murtaugh.Workers.PartitionReaper do
  use Oban.Worker, queue: :maintenance, max_attempts: 3

  @partitioned_tables ~w(events threats dlp_events device_events)

  @impl true
  def perform(%{args: %{"tenant_shard_id" => shard_id}}) do
    shard = Repo.get!(TenantShard, shard_id)
    repo = ShardManager.get_repo!(shard.id)
    TenantRepo.put_dynamic_repo(repo)

    for table <- @partitioned_tables do
      # 1. Create next month's partition if missing
      ensure_future_partition(repo, table)

      # 2. Find expired partitions
      cutoff = Date.utc_today() |> Date.add(-shard.retention_days)
      expired = list_partitions_before(repo, table, cutoff)

      for partition <- expired do
        # 3. Archive to object storage
        case Archive.Exporter.export_partition(shard, table, partition.name, partition.year_month) do
          {:ok, result} ->
            Logger.info("Archived #{partition.name}: #{result.rows} rows, #{result.size} bytes")

            # 4. Drop the partition
            TenantRepo.query!("DROP TABLE IF EXISTS #{partition.name}")
            Logger.info("Dropped partition #{partition.name}")

          {:error, reason} ->
            Logger.error("Failed to archive #{partition.name}: #{inspect(reason)}")
            # Do NOT drop — retry next run
        end
      end
    end

    :ok
  end
end
```

Key safety rule: **never drop a partition that hasn't been successfully
archived**. The export must succeed and the manifest must be updated
before the partition is dropped.

## Manifest

Each tenant has a manifest per table tracking all archived partitions.
Stored both in the meta DB (for fast queries) and as a JSON file alongside
the Parquet files in the bucket (for self-contained archives).

### Meta DB Schema

```sql
-- In murtaugh_meta

CREATE TABLE archive_manifests (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_shard_id UUID NOT NULL REFERENCES tenant_shards(id),
    table_name      TEXT NOT NULL,            -- events, threats, dlp_events, etc.
    year_month      TEXT NOT NULL,            -- "2026-01"
    object_key      TEXT NOT NULL,            -- full path in bucket
    file_size_bytes BIGINT NOT NULL,
    row_count       BIGINT NOT NULL,
    checksum        TEXT NOT NULL,            -- SHA-256 of the Parquet file
    archived_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL DEFAULT 'active',  -- active, restoring, deleted

    UNIQUE (tenant_shard_id, table_name, year_month)
);

CREATE INDEX idx_manifest_shard ON archive_manifests (tenant_shard_id, table_name);
```

### Bucket-Side Manifest

```json
// s3://murtaugh-archive/tenant-acme/events/manifest.json
{
  "tenant": "tenant-acme",
  "table": "events",
  "partitions": [
    {
      "year_month": "2026-01",
      "file": "2026-01.parquet",
      "size_bytes": 48291034,
      "row_count": 1284032,
      "checksum": "sha256:abc123...",
      "archived_at": "2026-04-01T03:00:00Z"
    },
    {
      "year_month": "2026-02",
      "file": "2026-02.parquet",
      "size_bytes": 52103948,
      "row_count": 1391204,
      "checksum": "sha256:def456...",
      "archived_at": "2026-05-01T03:00:00Z"
    }
  ]
}
```

## Querying Archived Data

Three approaches, from simplest to most powerful:

### 1. Download Parquet (Self-Service)

Users can download archived Parquet files directly from the UI:

```
/orgs/:slug/archive
```

Lists available archives by table and time range. Click to download.
The user opens them in DuckDB, Pandas, or whatever they use.

Presigned URLs ensure the download goes direct from the bucket to the
user's browser without passing through Murtaugh.

### 2. Restore to Tenant DB (Temporary)

For forensic investigation, restore an archived partition back into
the tenant DB as a temporary table:

```elixir
defmodule Murtaugh.Archive.Restorer do
  def restore_partition(tenant_shard, table, year_month, opts \\ []) do
    ttl_hours = Keyword.get(opts, :ttl_hours, 24)

    # Download Parquet from bucket
    key = "#{tenant_shard.name}/#{table}/#{year_month}.parquet"
    {:ok, body} = storage().get(bucket(), key)

    # Load into DataFrame
    tmp_path = Path.join(System.tmp_dir!(), "restore_#{table}_#{year_month}.parquet")
    File.write!(tmp_path, body)
    df = Explorer.DataFrame.from_parquet!(tmp_path)

    # Create temporary table in tenant DB
    temp_table = "#{table}_restored_#{String.replace(year_month, "-", "_")}"
    repo = ShardManager.get_repo!(tenant_shard.id)
    TenantRepo.put_dynamic_repo(repo)

    create_table_from_df(repo, temp_table, df)
    insert_df_rows(repo, temp_table, df)

    # Schedule cleanup
    Oban.insert(
      Murtaugh.Workers.DropRestoredPartition.new(
        %{shard_id: tenant_shard.id, table: temp_table},
        scheduled_at: DateTime.add(DateTime.utc_now(), ttl_hours * 3600)
      )
    )

    File.rm(tmp_path)

    {:ok, %{table: temp_table, rows: Explorer.DataFrame.n_rows(df), ttl_hours: ttl_hours}}
  end
end
```

The restored table appears in the event explorer with a badge indicating
it's archived data with an expiry time.

### 3. Query in Place (DuckDB / External Tools)

For advanced users, Parquet files in S3/GCS can be queried directly with:

```sql
-- DuckDB (local)
SELECT * FROM read_parquet('s3://murtaugh-archive/tenant-acme/events/2026-01.parquet')
WHERE process_name = 'curl'
AND severity = 'high';

-- BigQuery (external table)
CREATE EXTERNAL TABLE archive.events_2026_01
OPTIONS (format = 'PARQUET', uris = ['gs://murtaugh-archive/tenant-acme/events/2026-01.parquet']);

-- Athena (AWS)
-- Point at the S3 prefix, Athena reads Parquet natively
```

This is the most powerful option and requires no Murtaugh involvement.

## Legal Hold

When a compliance or legal hold is placed on an org node, archived data
under that subtree must not be deleted, even if the normal retention
policy would expire it.

```sql
-- In murtaugh_meta

CREATE TABLE legal_holds (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_node_id     UUID NOT NULL REFERENCES org_nodes(id),
    reason          TEXT NOT NULL,
    created_by      UUID REFERENCES users(id),
    active          BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    released_at     TIMESTAMPTZ
);
```

The PartitionReaper checks for active legal holds on the tenant's org
subtree before dropping or deleting any archived data:

```elixir
def can_purge_archive?(shard, table, year_month) do
  # Get all org nodes that use this shard
  org_nodes = Repo.all(from n in OrgNode, where: n.tenant_shard_id == ^shard.id)

  # Check if any node (or ancestor) has an active legal hold
  holds = for node <- org_nodes do
    Repo.exists?(
      from h in LegalHold,
        join: n in OrgNode, on: n.id == h.org_node_id,
        where: h.active == true,
        where: n.lft <= ^node.lft and n.rgt >= ^node.rgt
    )
  end

  not Enum.any?(holds)
end
```

## Archive Lifecycle Summary

```
 Day 0          Day 90              Day 90 + archive
   │               │                      │
   ▼               ▼                      ▼
 [LIVE]         [EXPIRED]            [ARCHIVED]
 Partition      Reaper runs:         Parquet in bucket
 in tenant      1. Export Parquet    Manifest updated
 DB             2. Upload            Partition dropped
                3. Update manifest
                4. Drop partition
                                          │
                                          │ Legal hold?
                                          │ No → purge after
                                          │      archive_retention
                                          │ Yes → keep forever
```

## Configuration

Per-tenant archive settings:

```sql
-- In tenant_shards table, add:
ALTER TABLE tenant_shards ADD COLUMN archive_enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE tenant_shards ADD COLUMN archive_retention_days INTEGER; -- null = keep forever
```

Global archive settings in the config:

```elixir
config :murtaugh, Murtaugh.Archive,
  enabled: true,
  storage: "s3",
  bucket: "murtaugh-archive",
  # ...storage credentials...
  compression: "zstd",          # Parquet compression codec
  max_concurrent_exports: 4     # Don't overwhelm the DB
```

## Dependencies

```elixir
# mix.exs
{:explorer, "~> 0.10"},           # Parquet read/write (Polars-backed)
{:ex_aws, "~> 2.5"},              # AWS API client
{:ex_aws_s3, "~> 2.5"},           # S3 operations
{:sweet_xml, "~> 0.7"},           # XML parsing for S3 responses
{:configparser_ex, "~> 4.0"},     # optional: parse AWS credentials file
```

For GCS-only deployments, `ex_aws_s3` works with the GCS S3-compatible
endpoint (`storage.googleapis.com`), so no additional dependency is needed.
For Azure, add `{:azure_storage, "~> 0.1"}`.
