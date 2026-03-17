defmodule Murtaugh.Detection.Storyline do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: false}
  @foreign_key_type :binary_id

  schema "storylines" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :root_pid, :integer
    field :root_process, :string
    field :root_path, :string
    field :status, :string, default: "active"
    field :max_severity, :string, default: "info"
    field :threat_count, :integer, default: 0
    field :event_count, :integer, default: 0
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :process_tree, :map
  end

  def changeset(storyline, attrs) do
    storyline
    |> cast(attrs, [
      :id,
      :agent_id,
      :org_node_id,
      :root_pid,
      :root_process,
      :root_path,
      :status,
      :max_severity,
      :threat_count,
      :event_count,
      :first_seen,
      :last_seen,
      :process_tree
    ])
    |> validate_required([:id, :agent_id, :org_node_id, :first_seen, :last_seen])
    |> validate_inclusion(:status, ~w(active resolved))
    |> validate_inclusion(:max_severity, ~w(info low medium high critical))
  end
end
