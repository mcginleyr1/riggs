defmodule Murtaugh.Tenancy do
  @moduledoc """
  Tenant resolution and scoped query execution.

  The main entry point for all tenant-scoped database work is `with_tenant/2`,
  which resolves the repo pool for a shard and sets the dynamic repo for the
  duration of the given function.
  """

  import Ecto.Query

  alias Murtaugh.Repo
  alias Murtaugh.TenantRepo
  alias Murtaugh.ShardManager
  alias Murtaugh.Org.Node, as: OrgNode

  @doc """
  Resolves the tenant shard for an org node.

  Walks up the nested set tree to find the nearest ancestor with a
  non-nil `tenant_shard_id`. If the node itself has a shard, returns that.
  """
  def resolve_shard(%OrgNode{lft: lft, rgt: rgt, tenant_shard_id: tenant_shard_id} = node) do
    if tenant_shard_id do
      {:ok, Repo.preload(node, :tenant_shard).tenant_shard}
    else
      ancestor =
        from(n in OrgNode,
          where: n.lft < ^lft and n.rgt > ^rgt,
          where: not is_nil(n.tenant_shard_id),
          order_by: [desc: n.lft],
          limit: 1,
          preload: [:tenant_shard]
        )
        |> Repo.one()

      case ancestor do
        nil -> {:error, :no_shard}
        %OrgNode{tenant_shard: shard} -> {:ok, shard}
      end
    end
  end

  @doc """
  Executes `fun` against the tenant database for the given shard.

  Sets the dynamic repo for `TenantRepo` so all queries inside `fun`
  route to the correct tenant database. Restores the previous dynamic
  repo (if any) after execution.

  Accepts a `%Murtaugh.Org.Shard{}` struct or a shard_id binary.
  """
  def with_tenant(shard_or_id, fun) do
    {:ok, pid} = ShardManager.get_repo(shard_or_id)
    previous = TenantRepo.get_dynamic_repo()

    try do
      TenantRepo.put_dynamic_repo(pid)
      fun.()
    after
      TenantRepo.put_dynamic_repo(previous)
    end
  end

  @doc """
  Creates the tenant database if it doesn't exist, then runs migrations.
  """
  def ensure_tenant_db(%{database_url: database_url} = shard) do
    %URI{path: "/" <> db_name} = URI.parse(database_url)
    base_url = String.replace(database_url, "/" <> db_name, "/postgres")

    {:ok, conn} = Postgrex.start_link(url: base_url)

    try do
      case Postgrex.query(conn, "SELECT 1 FROM pg_database WHERE datname = $1", [db_name]) do
        {:ok, %{num_rows: 0}} ->
          Postgrex.query!(conn, "CREATE DATABASE \"#{db_name}\"", [])
          enable_timescaledb(database_url)
          :created

        {:ok, _} ->
          :exists
      end
    after
      GenServer.stop(conn)
    end

    run_tenant_migrations(shard)
  end

  # Enable the TimescaleDB extension in a freshly created tenant database.
  # Must run before migrations because create_hypertable requires it.
  defp enable_timescaledb(database_url) do
    {:ok, conn} = Postgrex.start_link(url: database_url)

    try do
      Postgrex.query!(conn, "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE", [])
    after
      GenServer.stop(conn)
    end
  end

  @doc """
  Runs all tenant migrations from priv/tenant_repo/migrations against
  the given shard's database.
  """
  def run_tenant_migrations(shard) do
    {:ok, pid} = ShardManager.get_repo(shard)
    previous = TenantRepo.get_dynamic_repo()

    try do
      TenantRepo.put_dynamic_repo(pid)
      migrations_path = Application.app_dir(:murtaugh, "priv/tenant_repo/migrations")
      Ecto.Migrator.run(TenantRepo, migrations_path, :up, all: true, dynamic_repo: pid)
    after
      TenantRepo.put_dynamic_repo(previous)
    end
  end
end
