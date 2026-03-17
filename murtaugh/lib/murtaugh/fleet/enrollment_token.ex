defmodule Murtaugh.Fleet.EnrollmentToken do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "enrollment_tokens" do
    belongs_to :org_node, Murtaugh.Org.Node
    belongs_to :creator, Murtaugh.Accounts.User, foreign_key: :created_by

    field :token, :string
    field :label, :string
    field :uses_remaining, :integer
    field :expires_at, :utc_datetime

    timestamps(updated_at: false)
  end

  @required_fields ~w(org_node_id token)a
  @optional_fields ~w(label uses_remaining expires_at created_by)a

  def changeset(enrollment_token, attrs) do
    enrollment_token
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_number(:uses_remaining, greater_than: 0)
    |> unique_constraint(:token)
    |> foreign_key_constraint(:org_node_id)
    |> foreign_key_constraint(:created_by)
  end
end
