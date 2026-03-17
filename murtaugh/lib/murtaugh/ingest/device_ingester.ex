defmodule Murtaugh.Ingest.DeviceIngester do
  @moduledoc "Records device connect/disconnect/block events."

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Ingest.AgentRegistry

  def ingest_device_event(report) do
    case AgentRegistry.lookup(report.agent_id) do
      {:ok, shard, org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          row = %{
            id: Ecto.UUID.generate(),
            agent_id: report.agent_id,
            org_node_id: org_node_id,
            timestamp: now,
            device_type: report.device_type,
            action: report.action,
            vendor_id: report.vendor_id,
            product_id: report.product_id,
            serial_number: report.serial_number,
            device_class: report.device_class,
            manufacturer: report.manufacturer,
            product_name: report.product_name,
            policy_decision: report.policy_decision || "allow"
          }

          TenantRepo.insert_all("device_events", [row])
          :ok
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end
end
