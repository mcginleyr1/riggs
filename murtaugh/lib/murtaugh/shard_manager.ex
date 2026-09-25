defmodule Murtaugh.ShardManager do
  @moduledoc """
  Manages dynamic TenantRepo connection pools per shard.

  Pools are started lazily on first access and shut down after 30 minutes
  of inactivity. Each shard gets its own TenantRepo process with an
  independent connection pool.
  """
  use GenServer

  require Logger

  @idle_timeout_ms :timer.minutes(30)
  @sweep_interval_ms :timer.minutes(5)

  # -- Public API --

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
    case Map.get(state.repos, shard_id) do
      nil ->
        shard = shard_or_nil || fetch_shard!(shard_id)

        case start_repo(shard) do
          {:ok, pid} ->
            new_state = %{
              state
              | repos: Map.put(state.repos, shard_id, pid),
                last_access:
                  Map.put(state.last_access, shard_id, System.monotonic_time(:millisecond))
            }

            {:reply, {:ok, pid}, new_state}

          {:error, reason} ->
            {:reply, {:error, reason}, state}
        end

      pid ->
        if Process.alive?(pid) do
          new_state = %{
            state
            | last_access:
                Map.put(state.last_access, shard_id, System.monotonic_time(:millisecond))
          }

          {:reply, {:ok, pid}, new_state}
        else
          # Pool died unexpectedly; clean up and retry
          shard = shard_or_nil || fetch_shard!(shard_id)

          case start_repo(shard) do
            {:ok, new_pid} ->
              new_state = %{
                state
                | repos: Map.put(state.repos, shard_id, new_pid),
                  last_access:
                    Map.put(state.last_access, shard_id, System.monotonic_time(:millisecond))
              }

              {:reply, {:ok, new_pid}, new_state}

            {:error, reason} ->
              new_state = %{
                state
                | repos: Map.delete(state.repos, shard_id),
                  last_access: Map.delete(state.last_access, shard_id)
              }

              {:reply, {:error, reason}, new_state}
          end
        end
    end
  end

  @impl true
  def handle_call({:stop_repo, shard_id}, _from, state) do
    case Map.get(state.repos, shard_id) do
      nil ->
        {:reply, :ok, state}

      pid ->
        stop_repo_pid(pid, shard_id)

        new_state = %{
          state
          | repos: Map.delete(state.repos, shard_id),
            last_access: Map.delete(state.last_access, shard_id)
        }

        {:reply, :ok, new_state}
    end
  end

  @impl true
  def handle_info(:sweep_idle, state) do
    now = System.monotonic_time(:millisecond)

    idle_shards =
      Enum.filter(state.last_access, fn {_shard_id, last} ->
        now - last > @idle_timeout_ms
      end)
      |> Enum.map(&elem(&1, 0))

    new_state =
      Enum.reduce(idle_shards, state, fn shard_id, acc ->
        case Map.get(acc.repos, shard_id) do
          nil ->
            acc

          pid ->
            Logger.info("ShardManager: shutting down idle repo pool for shard #{shard_id}")
            stop_repo_pid(pid, shard_id)

            %{
              acc
              | repos: Map.delete(acc.repos, shard_id),
                last_access: Map.delete(acc.last_access, shard_id)
            }
        end
      end)

    schedule_sweep()
    {:noreply, new_state}
  end

  # -- Private --

  defp start_repo(shard) do
    Murtaugh.TenantRepo.start_link(
      name: nil,
      url: shard.database_url,
      pool_size: shard.pool_size || 10
    )
  end

  defp stop_repo_pid(pid, shard_id) do
    try do
      Supervisor.stop(pid, :normal, 5_000)
    catch
      :exit, _ ->
        Logger.warning("ShardManager: failed to cleanly stop repo for shard #{shard_id}")
        :ok
    end
  end

  defp fetch_shard!(shard_id) do
    Murtaugh.Repo.get!(Murtaugh.Org.Shard, shard_id)
  end

  defp schedule_sweep do
    Process.send_after(self(), :sweep_idle, @sweep_interval_ms)
  end
end
