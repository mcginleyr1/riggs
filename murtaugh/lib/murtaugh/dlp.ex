defmodule Murtaugh.Dlp do
  @moduledoc """
  DLP (Data Loss Prevention) context for tenant-scoped DLP event operations.
  """

  import Ecto.Query

  alias Murtaugh.TenantRepo
  alias Murtaugh.Tenancy
  alias Murtaugh.Dlp.Event

  def create_event(shard, attrs) do
    Tenancy.with_tenant(shard, fn ->
      %Event{}
      |> Event.changeset(attrs)
      |> TenantRepo.insert()
    end)
  end

  def list_events(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      limit = Keyword.get(opts, :limit, 50)
      agent_id = Keyword.get(opts, :agent_id)
      action = Keyword.get(opts, :action)
      domain = Keyword.get(opts, :domain)

      Event
      |> maybe_filter(:agent_id, agent_id)
      |> maybe_filter(:action, action)
      |> maybe_filter(:domain, domain)
      |> order_by([e], desc: e.timestamp)
      |> limit(^limit)
      |> TenantRepo.all()
    end)
  end

  def daily_counts(shard) do
    Tenancy.with_tenant(shard, fn ->
      thirty_days_ago =
        DateTime.utc_now()
        |> DateTime.add(-30 * 86_400, :second)
        |> DateTime.truncate(:second)

      from(e in Event,
        where: e.timestamp >= ^thirty_days_ago,
        group_by: fragment("date_trunc('day', ?)", e.timestamp),
        order_by: fragment("date_trunc('day', ?)", e.timestamp),
        select: %{
          date: fragment("date_trunc('day', ?)", e.timestamp),
          count: count(e.id)
        }
      )
      |> TenantRepo.all()
    end)
  end

  @doc "Count of blocked DLP events since midnight UTC (dashboard 'DLP BLOCKS')."
  def count_blocks_today(shard) do
    Tenancy.with_tenant(shard, fn ->
      start_of_day =
        DateTime.utc_now()
        |> DateTime.to_date()
        |> DateTime.new!(~T[00:00:00], "Etc/UTC")

      from(e in Event, where: e.action == "block" and e.timestamp >= ^start_of_day)
      |> TenantRepo.aggregate(:count, :id)
    end)
  end

  def recent_blocks(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      limit = Keyword.get(opts, :limit, 25)

      from(e in Event,
        where: e.action == "block",
        order_by: [desc: e.timestamp],
        limit: ^limit
      )
      |> TenantRepo.all()
    end)
  end

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, :agent_id, val), do: where(query, [e], e.agent_id == ^val)
  defp maybe_filter(query, :action, val), do: where(query, [e], e.action == ^val)
  defp maybe_filter(query, :domain, val), do: where(query, [e], e.domain == ^val)
end
