defmodule Murtaugh.Alerts.Integration do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id
  @timestamps_opts [type: :utc_datetime]

  schema "alert_integrations" do
    belongs_to :org_node, Murtaugh.Org.Node

    field :integration_type, :string
    field :name, :string
    field :config, :map
    field :enabled, :boolean, default: true
    field :severity_filter, {:array, :string}, default: ["suspicious", "malicious"]

    timestamps()
  end

  @required_fields ~w(org_node_id integration_type name config)a
  @optional_fields ~w(enabled severity_filter)a

  def changeset(integration, attrs) do
    integration
    |> cast(attrs, @required_fields ++ @optional_fields)
    |> validate_required(@required_fields)
    |> validate_inclusion(:integration_type, ~w(slack pagerduty email webhook))
    |> foreign_key_constraint(:org_node_id)
  end
end
