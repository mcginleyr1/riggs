defmodule Murtaugh.Archive.Manifest do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "archive_manifests" do
    belongs_to :tenant_shard, Murtaugh.Org.Shard

    field :table_name, :string
    field :year_month, :string
    field :object_key, :string
    field :file_size_bytes, :integer
    field :row_count, :integer
    field :checksum, :string
    field :status, :string, default: "pending"

    timestamps()
  end

  @required_fields ~w(tenant_shard_id table_name year_month object_key file_size_bytes row_count checksum)a
  @optional_fields ~w(status)a

  def changeset(manifest, attrs) do
    manifest
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:status, ~w(pending uploading completed failed))
    |> validate_format(:year_month, ~r/^\d{4}-\d{2}$/, message: "must be YYYY-MM format")
    |> validate_number(:file_size_bytes, greater_than: 0)
    |> validate_number(:row_count, greater_than_or_equal_to: 0)
    |> unique_constraint([:tenant_shard_id, :table_name, :year_month])
    |> foreign_key_constraint(:tenant_shard_id)
  end
end
