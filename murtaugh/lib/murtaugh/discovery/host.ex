defmodule Murtaugh.Discovery.Host do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "network_hosts" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :ip_address, :string
    field :mac_address, :string
    field :hostname, :string
    field :vendor, :string
    field :first_seen, :utc_datetime
    field :last_seen, :utc_datetime
    field :is_internal, :boolean, default: true
    field :open_ports, {:array, :integer}, default: []
  end

  def changeset(host, attrs) do
    host
    |> cast(attrs, [
      :agent_id,
      :org_node_id,
      :ip_address,
      :mac_address,
      :hostname,
      :vendor,
      :first_seen,
      :last_seen,
      :is_internal,
      :open_ports
    ])
    |> validate_required([:agent_id, :org_node_id, :ip_address, :first_seen, :last_seen])
    |> unique_constraint([:agent_id, :ip_address])
  end
end
