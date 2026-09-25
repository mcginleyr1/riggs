defmodule Murtaugh.Ingest.Heartbeat do
  @moduledoc "Updates agent health metrics from heartbeat messages."

  import Ecto.Query

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Fleet.Agent
  alias Murtaugh.Ingest.AgentRegistry

  def record_heartbeat(agent_id, health) do
    case AgentRegistry.lookup(agent_id) do
      {:ok, shard, _org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)
          attrs = health_attrs(health, now)

          {count, results} =
            TenantRepo.update_all(
              from(a in Agent, where: a.id == ^agent_id, select: a),
              set: Enum.to_list(attrs)
            )

          if count > 0 do
            agent = hd(results)

            Phoenix.PubSub.broadcast(
              Murtaugh.PubSub,
              Murtaugh.Topics.fleet(agent.org_node_id),
              {:agent_status_change, agent}
            )
          end

          :ok
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end

  defp health_attrs(nil, now), do: [status: "online", last_heartbeat: now]

  defp health_attrs(health, now) do
    [
      status: "online",
      last_heartbeat: now,
      events_processed: health.events_processed,
      threats_detected: health.threats_detected,
      dlp_blocks: health.dlp_blocks,
      sensor_healthy: health.sensor_healthy,
      pipeline_latency_us: health.pipeline_latency_us,
      store_size_bytes: health.store_size_bytes,
      uptime_secs: health.uptime_secs
    ]
  end
end
