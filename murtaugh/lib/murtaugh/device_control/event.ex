defmodule Murtaugh.DeviceControl.Event do
  use Ecto.Schema
  import Ecto.Changeset

  @primary_key {:id, :binary_id, autogenerate: true}
  @foreign_key_type :binary_id

  schema "device_events" do
    field :agent_id, :binary_id
    field :org_node_id, :binary_id
    field :timestamp, :utc_datetime
    field :device_type, :string
    field :action, :string
    field :vendor_id, :integer
    field :product_id, :integer
    field :serial_number, :string
    field :device_class, :string
    field :manufacturer, :string
    field :product_name, :string
    field :policy_decision, :string
  end

  def changeset(event, attrs) do
    event
    |> cast(attrs, [
      :agent_id,
      :org_node_id,
      :timestamp,
      :device_type,
      :action,
      :vendor_id,
      :product_id,
      :serial_number,
      :device_class,
      :manufacturer,
      :product_name,
      :policy_decision
    ])
    |> validate_required([
      :agent_id,
      :org_node_id,
      :timestamp,
      :device_type,
      :action,
      :policy_decision
    ])
  end
end
