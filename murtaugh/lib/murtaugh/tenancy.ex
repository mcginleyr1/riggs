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
  alias Murtaugh.Org
  alias Murtaugh.Org.Node, as: OrgNode
  alias Murtaugh.Org.Shard

  require Logger

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
  Provisions a tenant end to end: an account org node under `:parent` (the
  root node by default), its shard, and its database. The shard stays
  `provisioning` until the database is ready, so a failure is retried by
  `provision_all/0` on the next boot.

      create_tenant(%{name: "Acme Corp", slug: "acme"})
  """
  def create_tenant(%{name: name, slug: slug} = attrs) do
    db_name = "murtaugh_tenant_" <> String.replace(slug, "-", "_")
    url = tenant_database_url(db_name)
    %URI{host: host, port: port} = URI.parse(url)
    parent = attrs[:parent] || Repo.get_by!(OrgNode, node_type: "root")

    shard_attrs = %{
      name: db_name,
      database_url: url,
      database_name: db_name,
      host: host,
      port: port,
      status: "provisioning",
      retention_days: attrs[:retention_days] || 90
    }

    Ecto.Multi.new()
    |> Ecto.Multi.insert(:shard, Shard.changeset(%Shard{}, shard_attrs))
    |> Ecto.Multi.run(:node, fn _repo, %{shard: shard} ->
      Org.insert_child(parent, %{
        node_type: "account",
        name: name,
        slug: slug,
        tenant_shard_id: shard.id,
        metadata: attrs[:metadata] || %{}
      })
    end)
    |> Repo.transaction()
    |> case do
      {:ok, %{shard: shard, node: node}} -> {:ok, %{node: node, shard: provision!(shard)}}
      {:error, _step, changeset, _changes} -> {:error, changeset}
    end
  end

  @doc """
  Provisions or migrates every shard's database. Runs at boot so pending
  tenants are finished and new tenant migrations roll out on deploy. One
  unreachable tenant is logged and skipped rather than blocking the rest.
  """
  def provision_all do
    from(s in Shard, where: s.status in ["provisioning", "active"])
    |> Repo.all()
    |> Enum.each(fn shard ->
      try do
        provision!(shard)
      rescue
        e -> Logger.error("tenant #{shard.name} provisioning failed: #{Exception.message(e)}")
      end
    end)
  end

  @doc false
  def provision_all_on_boot do
    provision_all()
    :ignore
  end

  defp provision!(shard) do
    ensure_tenant_db(shard)

    if shard.status == "active",
      do: shard,
      else: shard |> Shard.changeset(%{status: "active"}) |> Repo.update!()
  end

  # New tenant DBs live on TENANT_DATABASE_* when configured, else on the meta
  # database's server.
  defp tenant_database_url(db_name) do
    cfg = Application.get_env(:murtaugh, :tenant_database) || Repo.config()
    userinfo = "#{URI.encode_www_form(cfg[:username])}:#{URI.encode_www_form(cfg[:password])}"

    URI.to_string(%URI{
      scheme: "postgres",
      userinfo: userinfo,
      host: cfg[:hostname],
      port: cfg[:port] || 5432,
      path: "/" <> db_name
    })
  end

  @doc """
  Creates the tenant database if it doesn't exist, then runs migrations.
  """
  def ensure_tenant_db(%{database_url: database_url} = shard) do
    %URI{path: "/" <> db_name} = URI.parse(database_url)

    # CREATE DATABASE can't be parameterized, so the name is interpolated below.
    # Validate it against a strict identifier allowlist to prevent injection via
    # a malformed/hostile shard URL.
    unless valid_db_name?(db_name) do
      raise ArgumentError, "unsafe tenant database name: #{inspect(db_name)}"
    end

    base_url = String.replace(database_url, "/" <> db_name, "/postgres")

    {:ok, conn} = Postgrex.start_link(Ecto.Repo.Supervisor.parse_url(base_url))

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

    result = run_tenant_migrations(shard)
    apply_retention_policy(shard)
    result
  end

  # Register a TimescaleDB retention policy so the operator-configured
  # retention_days is actually enforced (its background scheduler drops event
  # chunks older than the window). Idempotent; a later change to retention_days
  # needs the policy removed and re-added.
  defp apply_retention_policy(%{database_url: database_url, retention_days: days})
       when is_integer(days) and days > 0 do
    {:ok, conn} = Postgrex.start_link(Ecto.Repo.Supervisor.parse_url(database_url))

    try do
      Postgrex.query!(
        conn,
        "SELECT add_retention_policy('events', drop_after => INTERVAL '#{days} days', if_not_exists => true)",
        []
      )
    after
      GenServer.stop(conn)
    end

    :ok
  end

  defp apply_retention_policy(_shard), do: :ok

  defp valid_db_name?(name) do
    is_binary(name) and byte_size(name) in 1..63 and
      String.match?(name, ~r/\A[a-zA-Z_][a-zA-Z0-9_]*\z/)
  end

  # Enable the TimescaleDB extension in a freshly created tenant database.
  # Must run before migrations because create_hypertable requires it.
  defp enable_timescaledb(database_url) do
    {:ok, conn} = Postgrex.start_link(Ecto.Repo.Supervisor.parse_url(database_url))

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
