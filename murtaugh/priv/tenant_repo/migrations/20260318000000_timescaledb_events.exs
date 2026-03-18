defmodule Murtaugh.TenantRepo.Migrations.TimescaledbEvents do
  use Ecto.Migration

  def up do
    # Extension must exist before create_hypertable.
    # init-databases.sql handles new DBs; this covers dynamic tenant DBs
    # created by ShardManager after initial setup.
    execute "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE"

    # Convert events to a TimescaleDB hypertable partitioned by timestamp.
    # chunk_time_interval of 1 day keeps individual chunks small and fast
    # to query; adjust upward (e.g. 7 days) if write throughput is low.
    execute """
    SELECT create_hypertable(
      'events',
      'timestamp',
      chunk_time_interval => INTERVAL '1 day',
      if_not_exists => TRUE
    )
    """

    # Compress chunks older than 7 days. TimescaleDB columnar compression
    # typically achieves 10-20x reduction on event telemetry.
    # segment_by agent_id so queries scoped to a single agent don't
    # decompress unrelated segments.
    execute """
    ALTER TABLE events SET (
      timescaledb.compress,
      timescaledb.compress_orderby = 'timestamp DESC',
      timescaledb.compress_segmentby = 'agent_id, event_type'
    )
    """

    execute """
    SELECT add_compression_policy('events', INTERVAL '7 days', if_not_exists => TRUE)
    """

    # Continuous aggregate: per-minute event counts per org.
    # Powers the dashboard events/sec sparkline without scanning raw data.
    execute """
    CREATE MATERIALIZED VIEW IF NOT EXISTS events_per_minute
    WITH (timescaledb.continuous) AS
    SELECT
      time_bucket('1 minute', timestamp) AS bucket,
      org_node_id,
      event_type,
      count(*) AS event_count
    FROM events
    GROUP BY bucket, org_node_id, event_type
    WITH NO DATA
    """

    execute """
    SELECT add_continuous_aggregate_policy(
      'events_per_minute',
      start_offset => INTERVAL '1 hour',
      end_offset   => INTERVAL '1 minute',
      schedule_interval => INTERVAL '1 minute',
      if_not_exists => TRUE
    )
    """
  end

  def down do
    execute "SELECT remove_continuous_aggregate_policy('events_per_minute', if_exists => TRUE)"
    execute "DROP MATERIALIZED VIEW IF EXISTS events_per_minute"
    execute "SELECT remove_compression_policy('events', if_exists => TRUE)"
    # Cannot undo create_hypertable without dropping the table.
    # Intentionally left as a hypertable on rollback.
  end
end
