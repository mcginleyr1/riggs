defmodule Murtaugh.Vuln.Finding do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "vulnerabilities" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :cve_id, :string
    field :package_name, :string
    field :package_version, :string
    field :package_source, :string
    field :cvss_score, :float
    field :severity, :string
    field :fixed_version, :string
    field :scan_timestamp, :utc_datetime
    field :status, :string, default: "open"
  end

  def changeset(finding, attrs) do
    finding
    |> cast(attrs, [
      :agent_id,
      :org_node_id,
      :cve_id,
      :package_name,
      :package_version,
      :package_source,
      :cvss_score,
      :severity,
      :fixed_version,
      :scan_timestamp,
      :status
    ])
    |> validate_required([
      :agent_id,
      :org_node_id,
      :cve_id,
      :package_name,
      :package_version,
      :severity,
      :scan_timestamp
    ])
    |> validate_inclusion(:severity, ~w(low medium high critical))
    |> validate_inclusion(:status, ~w(open resolved ignored))
    |> unique_constraint([:agent_id, :cve_id, :package_name])
  end
end
