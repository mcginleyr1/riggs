defmodule Murtaugh.Org.Node do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "org_nodes" do
    field :node_type, :string
    field :name, :string
    field :slug, :string
    field :description, :string

    field :lft, :integer
    field :rgt, :integer
    field :depth, :integer, default: 0

    field :metadata, :map, default: %{}

    belongs_to :parent, __MODULE__
    belongs_to :tenant_shard, Murtaugh.Org.Shard

    has_many :children, __MODULE__, foreign_key: :parent_id
    has_many :user_grants, Murtaugh.Accounts.Grant, foreign_key: :org_node_id
    has_many :enrollment_tokens, Murtaugh.Fleet.EnrollmentToken, foreign_key: :org_node_id
    has_many :alert_integrations, Murtaugh.Alerts.Integration, foreign_key: :org_node_id
    has_many :legal_holds, Murtaugh.Legal.Hold, foreign_key: :org_node_id

    timestamps()
  end

  @required_fields ~w(node_type name slug lft rgt depth)a
  @optional_fields ~w(parent_id tenant_shard_id description metadata)a

  def changeset(node, attrs) do
    node
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:node_type, ~w(root account region site group))
    |> validate_format(:slug, ~r/^[a-z0-9][a-z0-9\-]*[a-z0-9]$|^[a-z0-9]$/,
      message: "must be lowercase alphanumeric with hyphens"
    )
    |> validate_number(:lft, greater_than_or_equal_to: 1)
    |> validate_number(:rgt, greater_than_or_equal_to: 2)
    |> validate_number(:depth, greater_than_or_equal_to: 0)
    |> unique_constraint(:slug)
    |> unique_constraint(:lft)
    |> unique_constraint(:rgt)
    |> foreign_key_constraint(:parent_id)
    |> foreign_key_constraint(:tenant_shard_id)
  end
end
