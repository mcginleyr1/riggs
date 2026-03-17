alias Murtaugh.Repo
alias Murtaugh.Org.{Node, Shard}
alias Murtaugh.Accounts.User

# Idempotent: only seed if no root node exists
unless Repo.get_by(Node, node_type: "root") do
  # Create the demo tenant shard
  {:ok, shard} =
    %Shard{}
    |> Shard.changeset(%{
      name: "shard-demo",
      database_url: "postgres://postgres:postgres@localhost:5432/murtaugh_tenant_demo",
      database_name: "murtaugh_tenant_demo",
      host: "localhost",
      port: 5432,
      pool_size: 10,
      status: "active",
      retention_days: 90
    })
    |> Repo.insert()

  # Create root org node (lft=1, rgt=6 to leave room for 2 children)
  {:ok, root} =
    %Node{}
    |> Node.changeset(%{
      node_type: "root",
      name: "Root",
      slug: "root",
      lft: 1,
      rgt: 6,
      depth: 0
    })
    |> Repo.insert()

  # Create a demo account node under root
  {:ok, _demo} =
    %Node{}
    |> Node.changeset(%{
      node_type: "account",
      name: "Demo Account",
      slug: "demo",
      parent_id: root.id,
      tenant_shard_id: shard.id,
      lft: 2,
      rgt: 3,
      depth: 1,
      metadata: %{"description" => "Default demo account for development"}
    })
    |> Repo.insert()

  # Create superadmin user
  {:ok, _admin} =
    %User{}
    |> User.registration_changeset(%{
      email: "admin@murtaugh.local",
      name: "Murtaugh Admin",
      password: "murtaugh",
      is_superadmin: true
    })
    |> Repo.insert()

  IO.puts("Seeded: root node, demo account (shard-demo), superadmin (admin@murtaugh.local)")
end
