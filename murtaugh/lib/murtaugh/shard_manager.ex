defmodule Murtaugh.ShardManager do
  @moduledoc """
  Manages dynamic TenantRepo connection pools per shard.

  Pools are started lazily on first access and shut down after 30 minutes
  of inactivity. Each shard gets its own TenantRepo process with an
  independent connection pool, running as a temporary child of
  `Murtaugh.TenantRepoSupervisor`. ShardManager monitors (does not link to)
  the pools, so one pool crashing only drops that pool; it is restarted on
  next use.
  """
  use GenServer

  require Logger

  @pool_supervisor Murtaugh.TenantRepoSupervisor
  @idle_timeout_ms :timer.minutes(30)
  @sweep_interval_ms :timer.minutes(5)

  # -- Public API --

  @doc """
  Child spec for the pool supervisor plus ShardManager. They restart together
  (one_for_all) so a ShardManager crash can't orphan pools it no longer tracks.
  """
  def supervisor_child_spec do
    children = [
      {DynamicSupervisor, name: @pool_supervisor, strategy: :one_for_one},
      __MODULE__
    ]

    %{
      id: Murtaugh.TenancySupervisor,
      type: :supervisor,
      start: {Supervisor, :start_link, [children, [strategy: :one_for_all]]}
    }
  end

  def start_link(opts) do
    GenServer.start_link(__MODULE__, opts, name: __MODULE__)
  end

  @doc """
  Returns `{:ok, pid}` for an existing pool or starts a new one.

  Accepts either a shard_id (binary UUID) which will be looked up from
  the meta DB, or a `%Murtaugh.Org.Shard{}` struct directly.
  """
  def get_repo(%{id: shard_id} = shard) do
    GenServer.call(__MODULE__, {:get_repo, shard_id, shard})
  end

  def get_repo(shard_id) when is_binary(shard_id) do
    GenServer.call(__MODULE__, {:get_repo, shard_id, nil})
  end

  @doc """
  Shuts down the repo pool for a specific shard.
  """
  def stop_repo(shard_id) when is_binary(shard_id) do
    GenServer.call(__MODULE__, {:stop_repo, shard_id})
  end

  # -- GenServer callbacks --

  @impl true
  def init(_opts) do
    schedule_sweep()
    {:ok, %{repos: %{}, last_access: %{}}}
  end

  @impl true
  def handle_call({:get_repo, shard_id, shard_or_nil}, _from, state) do
    now = System.monotonic_time(:millisecond)
    pid = Map.get(state.repos, shard_id)

    if pid && Process.alive?(pid) do
      {:reply, {:ok, pid}, %{state | last_access: Map.put(state.last_access, shard_id, now)}}
    else
      # Not started yet, or the pool died unexpectedly: (re)start it.
      case start_repo(shard_or_nil || fetch_shard!(shard_id)) do
        {:ok, new_pid} ->
          {:reply, {:ok, new_pid},
           %{
             state
             | repos: Map.put(state.repos, shard_id, new_pid),
               last_access: Map.put(state.last_access, shard_id, now)
           }}

        {:error, reason} ->
          {:reply, {:error, reason}, forget(state, shard_id)}
      end
    end
  end

  @impl true
  def handle_call({:stop_repo, shard_id}, _from, state) do
    if pid = Map.get(state.repos, shard_id), do: stop_repo_pid(pid, shard_id)
    {:reply, :ok, forget(state, shard_id)}
  end

  @impl true
  def handle_info(:sweep_idle, state) do
    now = System.monotonic_time(:millisecond)

    new_state =
      state.last_access
      |> Enum.filter(fn {_shard_id, last} -> now - last > @idle_timeout_ms end)
      |> Enum.reduce(state, fn {shard_id, _last}, acc ->
        if pid = Map.get(acc.repos, shard_id) do
          Logger.info("ShardManager: shutting down idle repo pool for shard #{shard_id}")
          stop_repo_pid(pid, shard_id)
        end

        forget(acc, shard_id)
      end)

    schedule_sweep()
    {:noreply, new_state}
  end

  @impl true
  def handle_info({:DOWN, _ref, :process, pid, reason}, state) do
    case Enum.find(state.repos, fn {_shard_id, repo_pid} -> repo_pid == pid end) do
      {shard_id, _pid} ->
        Logger.warning(
          "ShardManager: repo pool for shard #{shard_id} exited (#{inspect(reason)}); " <>
            "it will be restarted on next use"
        )

        {:noreply, forget(state, shard_id)}

      nil ->
        {:noreply, state}
    end
  end

  # -- Private --

  defp start_repo(shard) do
    opts = [name: nil, url: shard.database_url, pool_size: shard.pool_size || 10]

    spec = %{
      id: shard.id,
      start: {Murtaugh.TenantRepo, :start_link, [opts]},
      type: :supervisor,
      restart: :temporary
    }

    with {:ok, pid} <- DynamicSupervisor.start_child(@pool_supervisor, spec) do
      Process.monitor(pid)
      {:ok, pid}
    end
  end

  defp stop_repo_pid(pid, shard_id) do
    with {:error, :not_found} <- DynamicSupervisor.terminate_child(@pool_supervisor, pid) do
      Logger.warning("ShardManager: repo pool for shard #{shard_id} was already gone")
    end
  end

  defp forget(state, shard_id) do
    %{
      state
      | repos: Map.delete(state.repos, shard_id),
        last_access: Map.delete(state.last_access, shard_id)
    }
  end

  defp fetch_shard!(shard_id) do
    Murtaugh.Repo.get!(Murtaugh.Org.Shard, shard_id)
  end

  defp schedule_sweep do
    Process.send_after(self(), :sweep_idle, @sweep_interval_ms)
  end
end
