defmodule Murtaugh.Org.Shard do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "tenant_shards" do
    field :name, :string
    field :database_url, :string
    field :database_name, :string
    field :host, :string
    field :port, :integer, default: 5432
    field :pool_size, :integer, default: 10
    field :status, :string, default: "active"
    field :retention_days, :integer, default: 90
    field :archive_enabled, :boolean, default: false
    field :archive_retention_days, :integer, default: 365

    has_many :org_nodes, Murtaugh.Org.Node, foreign_key: :tenant_shard_id
    has_many :archive_manifests, Murtaugh.Archive.Manifest, foreign_key: :tenant_shard_id

    timestamps()
  end

  @required_fields ~w(name database_url database_name host)a
  @optional_fields ~w(port pool_size status retention_days archive_enabled archive_retention_days)a

  def changeset(shard, attrs) do
    shard
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, ~w(active migrating archived))
    |> validate_number(:port, greater_than: 0, less_than: 65536)
    |> validate_number(:pool_size, greater_than: 0)
    |> validate_number(:retention_days, greater_than: 0)
    |> validate_number(:archive_retention_days, greater_than: 0)
    |> unique_constraint(:name)
  end
end
