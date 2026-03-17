defmodule Murtaugh.Policy.Template do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "policy_templates" do
    field :name, :string
    field :policy_type, :string
    field :content, :string
    field :version, :integer, default: 1

    belongs_to :creator, Murtaugh.Accounts.User, foreign_key: :created_by

    timestamps()
  end

  @required_fields ~w(name policy_type content)a
  @optional_fields ~w(version created_by)a

  def changeset(template, attrs) do
    template
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:policy_type, ~w(dlp response detection device config))
    |> validate_number(:version, greater_than: 0)
    |> unique_constraint(:name)
    |> foreign_key_constraint(:created_by)
  end
end
