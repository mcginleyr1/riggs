defmodule Murtaugh.Response.Action do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "response_actions" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :threat_id, :binary_id
    field :action_type, :string
    field :target, :string
    field :initiated_by, :string
    field :success, :boolean
    field :detail, :string
    field :timestamp, :utc_datetime
  end

  def changeset(action, attrs) do
    action
    |> cast(attrs, [
      :agent_id,
      :org_node_id,
      :threat_id,
      :action_type,
      :target,
      :initiated_by,
      :success,
      :detail,
      :timestamp
    ])
    |> validate_required([
      :agent_id,
      :org_node_id,
      :action_type,
      :target,
      :initiated_by,
      :success
    ])
  end
end
