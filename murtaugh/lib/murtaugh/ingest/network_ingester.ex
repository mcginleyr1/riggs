defmodule Murtaugh.Ingest.NetworkIngester do
  @moduledoc "Upserts discovered network hosts from agent network maps."

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Ingest.AgentRegistry

  def update_network_map(update) do
    case AgentRegistry.lookup(update.agent_id) do
      {:ok, shard, org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          rows =
            Enum.map(update.hosts || [], fn host ->
              %{
                id: Ecto.UUID.generate(),
                agent_id: update.agent_id,
                org_node_id: org_node_id,
                ip_address: host.ip_address,
                mac_address: host.mac_address,
                hostname: host.hostname,
                vendor: host.vendor,
                first_seen: now,
                last_seen: now,
                is_internal: true,
                open_ports: host.open_ports || []
              }
            end)

          TenantRepo.insert_all("network_hosts", rows,
            on_conflict: {:replace, [:hostname, :vendor, :last_seen, :open_ports, :mac_address]},
            conflict_target: [:agent_id, :ip_address]
          )

          :ok
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end
end
