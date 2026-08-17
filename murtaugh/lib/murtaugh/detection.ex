defmodule Murtaugh.Detection do
  @moduledoc """
  Detection context for tenant-scoped threat and storyline operations.
  """

  import Ecto.Query

  alias Murtaugh.TenantRepo
  alias Murtaugh.Tenancy
  alias Murtaugh.Detection.{Threat, Storyline}

  def create_threat(shard, attrs) do
    Tenancy.with_tenant(shard, fn ->
      %Threat{}
      |> Threat.changeset(attrs)
      |> TenantRepo.insert()
    end)
  end

  def list_threats(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      limit = Keyword.get(opts, :limit, 50)
      status = Keyword.get(opts, :status)
      threat_level = Keyword.get(opts, :threat_level)
      agent_id = Keyword.get(opts, :agent_id)

      Threat
      |> maybe_filter_status(status)
      |> maybe_filter_level(threat_level)
      |> maybe_filter_agent(agent_id)
      |> order_by([t], desc: t.timestamp)
      |> limit(^limit)
      |> TenantRepo.all()
    end)
  end

  def update_threat_status(shard, threat_id, attrs) do
    Tenancy.with_tenant(shard, fn ->
      threat = TenantRepo.get!(Threat, threat_id)

      threat
      |> Threat.status_changeset(attrs)
      |> TenantRepo.update()
    end)
  end

  def get_storyline!(shard, storyline_id) do
    Tenancy.with_tenant(shard, fn ->
      TenantRepo.get!(Storyline, storyline_id)
    end)
  end

  defp maybe_filter_status(query, nil), do: query
  defp maybe_filter_status(query, status), do: where(query, [t], t.status == ^status)

  defp maybe_filter_level(query, nil), do: query
  defp maybe_filter_level(query, level), do: where(query, [t], t.threat_level == ^level)

  def get_threat!(shard, threat_id) do
    Tenancy.with_tenant(shard, fn ->
      TenantRepo.get!(Threat, threat_id)
    end)
  end

  def count_threats_today(shard) do
    Tenancy.with_tenant(shard, fn ->
      start_of_day =
        DateTime.utc_now()
        |> DateTime.to_date()
        |> DateTime.new!(~T[00:00:00], "Etc/UTC")

      from(t in Threat, where: t.timestamp >= ^start_of_day)
      |> TenantRepo.aggregate(:count, :id)
    end)
  end

  def list_events(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      events_query(opts)
      |> order_by([e], desc: e.timestamp)
      |> limit(^Keyword.get(opts, :limit, 100))
      |> offset(^Keyword.get(opts, :offset, 0))
      |> select([e], %{
        id: e.id,
        timestamp: e.timestamp,
        event_type: e.event_type,
        severity: e.severity,
        process_name: e.process_name,
        process_path: e.process_path,
        cmdline: e.cmdline,
        agent_id: e.agent_id,
        payload: e.payload
      })
      |> TenantRepo.all()
    end)
  end

  @doc "Total events matching the same filters as `list_events/2` (for pagination)."
  def count_events(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      events_query(opts) |> TenantRepo.aggregate(:count, :id)
    end)
  end

  # Shared filter chain for list_events/count_events so both see the same set.
  defp events_query(opts) do
    from(e in "events")
    |> maybe_filter_agent_raw(Keyword.get(opts, :agent_id))
    |> maybe_filter_event_type(Keyword.get(opts, :event_type))
    |> maybe_filter_severity_str(Keyword.get(opts, :severity))
    |> maybe_filter_since(Keyword.get(opts, :since))
    |> maybe_search_events(Keyword.get(opts, :search))
  end

  defp maybe_filter_agent_raw(query, nil), do: query
  defp maybe_filter_agent_raw(query, agent_id), do: where(query, [e], e.agent_id == ^agent_id)

  defp maybe_filter_event_type(query, type) when type in [nil, "", "all"], do: query
  defp maybe_filter_event_type(query, type), do: where(query, [e], e.event_type == ^type)

  defp maybe_filter_severity_str(query, sev) when sev in [nil, "", "all"], do: query
  defp maybe_filter_severity_str(query, sev), do: where(query, [e], e.severity == ^sev)

  defp maybe_filter_since(query, nil), do: query
  defp maybe_filter_since(query, %DateTime{} = since), do: where(query, [e], e.timestamp >= ^since)

  defp maybe_search_events(query, term) when term in [nil, ""], do: query

  defp maybe_search_events(query, term) do
    like = "%#{term}%"

    where(
      query,
      [e],
      ilike(e.process_name, ^like) or ilike(e.process_path, ^like) or
        ilike(e.cmdline, ^like) or ilike(e.event_type, ^like)
    )
  end

  defp maybe_filter_agent(query, nil), do: query
  defp maybe_filter_agent(query, agent_id), do: where(query, [t], t.agent_id == ^agent_id)
end
