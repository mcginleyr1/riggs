defmodule Murtaugh.Fleet do
  @moduledoc """
  Fleet management context for tenant-scoped agent operations.
  """

  import Ecto.Query

  alias Murtaugh.TenantRepo
  alias Murtaugh.Tenancy
  alias Murtaugh.Fleet.Agent

  def list_agents(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      limit = Keyword.get(opts, :limit, 100)
      status = Keyword.get(opts, :status)
      org_node_id = Keyword.get(opts, :org_node_id)

      Agent
      |> maybe_filter_status(status)
      |> maybe_filter_org_node(org_node_id)
      |> order_by([a], desc: a.last_heartbeat)
      |> limit(^limit)
      |> TenantRepo.all()
    end)
  end

  def get_agent!(shard, agent_id) do
    Tenancy.with_tenant(shard, fn ->
      TenantRepo.get!(Agent, agent_id)
    end)
  end

  def create_agent(shard, attrs) do
    Tenancy.with_tenant(shard, fn ->
      %Agent{}
      |> Agent.changeset(attrs)
      |> TenantRepo.insert()
    end)
  end

  def update_agent_health(shard, %Agent{} = agent, attrs) do
    Tenancy.with_tenant(shard, fn ->
      agent
      |> Agent.health_changeset(attrs)
      |> TenantRepo.update()
    end)
  end

  def update_agent_health(shard, agent_id, attrs) when is_binary(agent_id) do
    Tenancy.with_tenant(shard, fn ->
      agent = TenantRepo.get!(Agent, agent_id)

      agent
      |> Agent.health_changeset(attrs)
      |> TenantRepo.update()
    end)
  end

  defp maybe_filter_status(query, nil), do: query
  defp maybe_filter_status(query, status), do: where(query, [a], a.status == ^status)

  defp maybe_filter_org_node(query, nil), do: query

  defp maybe_filter_org_node(query, org_node_id),
    do: where(query, [a], a.org_node_id == ^org_node_id)
end
