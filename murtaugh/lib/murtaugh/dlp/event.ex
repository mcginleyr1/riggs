defmodule Murtaugh.Dlp.Event do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "dlp_events" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :timestamp, :utc_datetime
    field :received_at, :utc_datetime
    field :action, :string
    field :pid, :integer
    field :process_name, :string
    field :file_path, :string
    field :file_type, :string
    field :domain, :string
    field :domain_category, :string
    field :username, :string
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :agent_id,
      :org_node_id,
      :timestamp,
      :received_at,
      :action,
      :pid,
      :process_name,
      :file_path,
      :file_type,
      :domain,
      :domain_category,
      :username
    ])
    |> validate_required([
      :agent_id,
      :org_node_id,
      :timestamp,
      :action,
      :pid,
      :process_name,
      :file_path,
      :file_type,
      :domain
    ])
    |> validate_inclusion(:action, ~w(block alert log))
  end
end
