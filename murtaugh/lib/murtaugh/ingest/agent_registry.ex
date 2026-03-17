defmodule Murtaugh.Ingest.AgentRegistry do
  @moduledoc """
  ETS cache mapping agent_id → {shard, org_node_id}.

  Populated at enrollment. Subsequent gRPC requests use this to route
  to the correct tenant shard without a meta DB round-trip.
  """
  use GenServer

  def start_link(_opts), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @impl GenServer
  def init(_) do
    table = :ets.new(__MODULE__, [:named_table, :public, :set, read_concurrency: true])
    {:ok, table}
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
end
