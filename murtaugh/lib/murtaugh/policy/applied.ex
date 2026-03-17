defmodule Murtaugh.Policy.Applied do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "applied_policies" do
    field :agent_id, :binary_id
    field :policy_type, :string
    field :policy_name, :string
    field :content_hash, :string
    field :version, :integer
    field :applied_at, :utc_datetime
    field :status, :string, default: "pending"
  end

  def changeset(applied, attrs) do
    applied
    |> cast(attrs, [
      :agent_id,
      :policy_type,
      :policy_name,
      :content_hash,
      :version,
      :applied_at,
      :status
    ])
    |> validate_required([
      :agent_id,
      :policy_type,
      :policy_name,
      :content_hash,
      :version
    ])
    |> validate_inclusion(:status, ~w(pending applied failed))
    |> unique_constraint([:agent_id, :policy_type])
  end
end
