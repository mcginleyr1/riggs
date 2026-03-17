defmodule Murtaugh.Telemetry do
  @moduledoc """
  Telemetry context for tenant-scoped event ingestion and querying.
  """

  import Ecto.Query

  alias Murtaugh.TenantRepo
  alias Murtaugh.Tenancy
  alias Murtaugh.Telemetry.Event

  def ingest_events(shard, events_list) when is_list(events_list) do
    Tenancy.with_tenant(shard, fn ->
      now = DateTime.utc_now() |> DateTime.truncate(:second)

      results =
        Enum.map(events_list, fn attrs ->
          attrs = Map.put_new(attrs, :received_at, now)

          %Event{}
          |> Event.changeset(attrs)
          |> TenantRepo.insert()
        end)

      successes = Enum.count(results, &match?({:ok, _}, &1))
      failures = Enum.count(results, &match?({:error, _}, &1))
      {:ok, %{inserted: successes, failed: failures}}
    end)
  end

  def list_events(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      limit = Keyword.get(opts, :limit, 50)
      agent_id = Keyword.get(opts, :agent_id)
      event_type = Keyword.get(opts, :event_type)
      severity = Keyword.get(opts, :severity)
      from_ts = Keyword.get(opts, :from)
      to_ts = Keyword.get(opts, :to)

      Event
      |> maybe_filter(:agent_id, agent_id)
      |> maybe_filter(:event_type, event_type)
      |> maybe_filter(:severity, severity)
      |> maybe_filter_from(from_ts)
      |> maybe_filter_to(to_ts)
      |> order_by([e], desc: e.timestamp)
      |> limit(^limit)
      |> TenantRepo.all()
    end)
  end

  def throughput(shard) do
    Tenancy.with_tenant(shard, fn ->
      one_hour_ago =
        DateTime.utc_now()
        |> DateTime.add(-3600, :second)
        |> DateTime.truncate(:second)

      from(e in Event,
        where: e.received_at >= ^one_hour_ago,
        select: count(e.id)
      )
      |> TenantRepo.one()
    end)
  end

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, :agent_id, val), do: where(query, [e], e.agent_id == ^val)
  defp maybe_filter(query, :event_type, val), do: where(query, [e], e.event_type == ^val)
  defp maybe_filter(query, :severity, val), do: where(query, [e], e.severity == ^val)

  defp maybe_filter_from(query, nil), do: query
  defp maybe_filter_from(query, ts), do: where(query, [e], e.timestamp >= ^ts)

  defp maybe_filter_to(query, nil), do: query
  defp maybe_filter_to(query, ts), do: where(query, [e], e.timestamp <= ^ts)
end
