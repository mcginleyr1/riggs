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
      limit = Keyword.get(opts, :limit, 100)
      agent_id = Keyword.get(opts, :agent_id)

      "events"
      |> maybe_filter_agent_raw(agent_id)
      |> order_by([e], desc: e.timestamp)
      |> limit(^limit)
      |> TenantRepo.all()
    end)
  end

  defp maybe_filter_agent_raw(query, nil), do: from(e in query)
  defp maybe_filter_agent_raw(query, agent_id), do: from(e in query, where: e.agent_id == ^agent_id)

  defp maybe_filter_agent(query, nil), do: query
  defp maybe_filter_agent(query, agent_id), do: where(query, [t], t.agent_id == ^agent_id)
end
