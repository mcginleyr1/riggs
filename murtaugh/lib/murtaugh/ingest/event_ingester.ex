defmodule Murtaugh.Ingest.EventIngester do
  @moduledoc "Batch-inserts telemetry events into the tenant events table."

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Ingest.AgentRegistry

  def ingest_events(agent_id, events) do
    case AgentRegistry.lookup(agent_id) do
      {:ok, shard, org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)
          rows = Enum.map(events, &to_row(&1, agent_id, org_node_id, now))

          {count, _} =
            TenantRepo.insert_all("events", rows,
              on_conflict: :nothing,
              conflict_target: [:id]
            )

          Phoenix.PubSub.broadcast(
            Murtaugh.PubSub,
            Murtaugh.Topics.throughput(org_node_id),
            {:events_ingested, count}
          )

          {:ok, count}
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end

  defp to_row(event, agent_id, org_node_id, now) do
    ctx = event[:process_context] || %{}

    %{
      id: coerce_uuid(event[:event_id]),
      agent_id: agent_id,
      org_node_id: org_node_id,
      storyline_id: coerce_uuid(event[:storyline_id]),
      event_type: event[:event_type] || "unknown",
      severity: event[:severity] || "info",
      timestamp: now,
      received_at: now,
      pid: ctx[:pid],
      ppid: ctx[:parent_pid],
      process_name: ctx[:name],
      process_path: ctx[:path],
      cmdline: ctx[:cmd_line],
      username: ctx[:username],
      payload: decode_payload(event[:payload_json])
    }
  end

  defp decode_payload(map) when is_map(map), do: map

  defp decode_payload(bin) when is_binary(bin) and bin != "" do
    case Jason.decode(bin) do
      {:ok, map} -> map
      _ -> %{}
    end
  end

  defp decode_payload(_), do: %{}

  defp coerce_uuid(nil), do: Ecto.UUID.generate()
  defp coerce_uuid(""), do: Ecto.UUID.generate()

  defp coerce_uuid(s) do
    case Ecto.UUID.cast(s) do
      {:ok, uuid} -> uuid
      :error -> Ecto.UUID.generate()
    end
  end
end
