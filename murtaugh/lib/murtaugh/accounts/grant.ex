defmodule Murtaugh.Accounts.Grant do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "user_grants" do
    belongs_to :user, Murtaugh.Accounts.User
    belongs_to :org_node, Murtaugh.Org.Node

    field :role, :string

    timestamps(updated_at: false)
  end

  @required_fields ~w(user_id org_node_id role)a

  def changeset(grant, attrs) do
    grant
    |> cast(attrs, @required_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:role, ~w(admin analyst viewer))
    |> unique_constraint([:user_id, :org_node_id])
    |> foreign_key_constraint(:user_id)
    |> foreign_key_constraint(:org_node_id)
  end
end
