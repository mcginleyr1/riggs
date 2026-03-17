defmodule Murtaugh.Fleet.Agent do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "agents" do
    field :org_node_id, :binary_id
    field :hostname, :string
    field :os, :string
    field :os_version, :string
    field :arch, :string
    field :agent_version, :string
    field :ip_address, :string
    field :mac_address, :string
    field :status, :string, default: "unknown"
    field :last_heartbeat, :utc_datetime
    field :enrolled_at, :utc_datetime
    field :config_version, :integer, default: 0
    field :tags, {:array, :string}, default: []
    field :metadata, :map, default: %{}

    field :events_processed, :integer, default: 0
    field :threats_detected, :integer, default: 0
    field :dlp_blocks, :integer, default: 0
    field :sensor_healthy, :boolean, default: true
    field :pipeline_latency_us, :integer, default: 0
    field :store_size_bytes, :integer, default: 0
    field :uptime_secs, :integer, default: 0
  end

  def changeset(agent, attrs) do
    agent
    |> cast(attrs, [
      :org_node_id,
      :hostname,
      :os,
      :os_version,
      :arch,
      :agent_version,
      :ip_address,
      :mac_address,
      :status,
      :last_heartbeat,
      :enrolled_at,
      :config_version,
      :tags,
      :metadata,
      :events_processed,
      :threats_detected,
      :dlp_blocks,
      :sensor_healthy,
      :pipeline_latency_us,
      :store_size_bytes,
      :uptime_secs
    ])
    |> validate_required([:org_node_id, :hostname, :os, :agent_version])
    |> validate_inclusion(:status, ~w(unknown online offline degraded decommissioned))
  end

  def health_changeset(agent, attrs) do
    agent
    |> cast(attrs, [
      :status,
      :last_heartbeat,
      :sensor_healthy,
      :pipeline_latency_us,
      :store_size_bytes,
      :uptime_secs,
      :events_processed,
      :threats_detected,
      :dlp_blocks
    ])
    |> validate_inclusion(:status, ~w(unknown online offline degraded decommissioned))
  end
end
