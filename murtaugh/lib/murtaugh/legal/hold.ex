defmodule Murtaugh.Legal.Hold do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "legal_holds" do
    belongs_to :org_node, Murtaugh.Org.Node
    belongs_to :creator, Murtaugh.Accounts.User, foreign_key: :created_by

    field :reason, :string
    field :active, :boolean, default: true
    field :released_at, :utc_datetime

    timestamps()
  end

  @required_fields ~w(org_node_id created_by reason)a
  @optional_fields ~w(active released_at)a

  def changeset(hold, attrs) do
    hold
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> foreign_key_constraint(:org_node_id)
    |> foreign_key_constraint(:created_by)
  end
end
