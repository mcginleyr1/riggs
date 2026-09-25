defmodule Murtaugh.TenancyTest do
  # Creates real tenant databases (outside the sandbox) and drops them after.
  use Murtaugh.DataCase

  alias Murtaugh.{Org, ShardManager, Tenancy, TenantRepo}
  alias Murtaugh.Org.{Node, Shard}

  setup do
    {:ok, root} =
      Org.create_node(%{node_type: "root", name: "Root", slug: "root", lft: 1, rgt: 2})

    %{root: root}
  end

  defp drop_on_exit(%Shard{id: id, database_name: db}) do
    on_exit(fn ->
      ShardManager.stop_repo(id)

      Ecto.Adapters.SQL.Sandbox.unboxed_run(Murtaugh.Repo, fn ->
        Ecto.Adapters.SQL.query!(Murtaugh.Repo, "DROP DATABASE IF EXISTS #{db} WITH (FORCE)")
      end)
    end)
  end

  defp bounds(slug) do
    node = Repo.get_by!(Node, slug: slug)
    {node.lft, node.rgt, node.depth}
  end

  test "insert_child keeps the nested set consistent", %{root: root} do
    {:ok, a} = Repo.transaction(fn -> Org.insert_child(root, child("a")) |> ok!() end)
    {:ok, _} = Repo.transaction(fn -> Org.insert_child(a, child("a1")) |> ok!() end)
    {:ok, _} = Repo.transaction(fn -> Org.insert_child(root, child("b")) |> ok!() end)
    {:ok, _} = Repo.transaction(fn -> Org.insert_child(a, child("a2")) |> ok!() end)

    assert bounds("root") == {1, 10, 0}
    assert bounds("a") == {2, 7, 1}
    assert bounds("a1") == {3, 4, 2}
    assert bounds("a2") == {5, 6, 2}
    assert bounds("b") == {8, 9, 1}
  end

  test "create_tenant provisions the node, shard and a migrated database" do
    assert {:ok, %{node: node, shard: shard}} =
             Tenancy.create_tenant(%{name: "Acme Corp", slug: "acme-corp"})

    drop_on_exit(shard)

    assert shard.status == "active"
    assert shard.database_name == "murtaugh_tenant_acme_corp"
    assert node.tenant_shard_id == shard.id and node.node_type == "account"
    assert bounds("root") == {1, 4, 0}
    assert {:ok, %Shard{id: id}} = Tenancy.resolve_shard(node)
    assert id == shard.id

    assert %{rows: [[0]]} =
             Tenancy.with_tenant(shard, fn -> TenantRepo.query!("SELECT count(*) FROM events") end)
  end

  test "provision_all finishes shards left in provisioning" do
    db = "murtaugh_tenant_pending_#{System.unique_integer([:positive])}"
    cfg = Repo.config()

    shard =
      Repo.insert!(%Shard{
        name: db,
        database_name: db,
        host: cfg[:hostname],
        status: "provisioning",
        database_url:
          "postgres://#{cfg[:username]}:#{cfg[:password]}@#{cfg[:hostname]}:#{cfg[:port]}/#{db}"
      })

    drop_on_exit(shard)

    Tenancy.provision_all()

    assert Repo.reload!(shard).status == "active"
  end

  defp child(slug), do: %{node_type: "group", name: slug, slug: slug}

  defp ok!({:ok, value}), do: value
end
