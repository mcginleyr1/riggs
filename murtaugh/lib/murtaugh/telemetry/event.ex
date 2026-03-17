defmodule Murtaugh.Telemetry.Event do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "events" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :storyline_id, :binary_id
    field :event_type, :string
    field :severity, :string
    field :timestamp, :utc_datetime
    field :received_at, :utc_datetime
    field :pid, :integer
    field :ppid, :integer
    field :process_name, :string
    field :process_path, :string
    field :cmdline, :string
    field :username, :string
    field :payload, :map
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :agent_id,
      :org_node_id,
      :storyline_id,
      :event_type,
      :severity,
      :timestamp,
      :received_at,
      :pid,
      :ppid,
      :process_name,
      :process_path,
      :cmdline,
      :username,
      :payload
    ])
    |> validate_required([
      :agent_id,
      :org_node_id,
      :storyline_id,
      :event_type,
      :severity,
      :timestamp,
      :payload
    ])
    |> validate_inclusion(:severity, ~w(info low medium high critical))
  end
end
