defmodule Murtaugh.Ingest.AgentRegistry do
  @moduledoc """
  ETS cache mapping agent_id → {shard, org_node_id}.

  Populated at enrollment. Subsequent gRPC requests use this to route
  to the correct tenant shard without a meta DB round-trip.

  On startup the table is rebuilt from the tenant databases, so a console
  restart does not strand the already-enrolled fleet (agents rarely re-enroll,
  and an ingest cache miss is rejected as `:unknown_agent`).
  """
  use GenServer

  import Ecto.Query
  require Logger

  alias Murtaugh.{Repo, Tenancy, TenantRepo}
  alias Murtaugh.Org.Shard
  alias Murtaugh.Fleet.Agent

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @impl GenServer
  def init(_) do
    table = :ets.new(__MODULE__, [:named_table, :public, :set, read_concurrency: true])
    {:ok, table, {:continue, :rebuild}}
  end

  @impl GenServer
  def handle_continue(:rebuild, table) do
    rebuild_from_db()
    {:noreply, table}
  end

  def register(agent_id, shard, org_node_id) do
    :ets.insert(__MODULE__, {agent_id, shard, org_node_id})
    :ok
  end

  def lookup(agent_id) do
    case :ets.lookup(__MODULE__, agent_id) do
      [{^agent_id, shard, org_node_id}] -> {:ok, shard, org_node_id}
      [] -> :error
    end
  end

  def forget(agent_id) do
    :ets.delete(__MODULE__, agent_id)
    :ok
  end

  # Repopulate the routing cache from every tenant database. Per-shard failures
  # are isolated so one unreachable shard does not abort the whole rebuild;
  # affected agents simply re-enroll on their next connection.
  defp rebuild_from_db do
    shards = Repo.all(from(s in Shard, where: s.status in ["active", "migrating"]))
    total = Enum.reduce(shards, 0, fn shard, acc -> acc + rebuild_shard(shard) end)
    Logger.info("AgentRegistry rebuilt: #{total} agents across #{length(shards)} shards")
  rescue
    e -> Logger.error("AgentRegistry rebuild failed: #{inspect(e)}")
  end

  defp rebuild_shard(shard) do
    agents =
      Tenancy.with_tenant(shard, fn ->
        TenantRepo.all(from(a in Agent, select: {a.id, a.org_node_id}))
      end)

    Enum.each(agents, fn {agent_id, org_node_id} -> register(agent_id, shard, org_node_id) end)
    length(agents)
  rescue
    e ->
      Logger.error("AgentRegistry rebuild failed for shard #{shard.id}: #{inspect(e)}")
      0
  end
end
