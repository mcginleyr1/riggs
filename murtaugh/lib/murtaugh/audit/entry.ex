defmodule Murtaugh.Audit.Entry do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "audit_log" do
    belongs_to :user, Murtaugh.Accounts.User
    belongs_to :org_node, Murtaugh.Org.Node

    field :action, :string
    field :target_type, :string
    field :target_id, :binary_id
    field :detail, :map
    field :timestamp, :utc_datetime
  end

  @required_fields ~w(action timestamp)a
  @optional_fields ~w(user_id org_node_id target_type target_id detail)a

  def changeset(entry, attrs) do
    entry
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:org_node_id)
  end
end
