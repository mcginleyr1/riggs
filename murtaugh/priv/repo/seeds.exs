alias Murtaugh.Repo
alias Murtaugh.Org.{Node, Shard}
alias Murtaugh.Accounts.User
alias Murtaugh.Fleet.EnrollmentToken

# Idempotent: only seed if no root node exists
unless Repo.get_by(Node, node_type: "root") do
  db_host = System.get_env("TENANT_DATABASE_HOST", "localhost")
  db_user = System.get_env("TENANT_DATABASE_USER", "postgres")
  db_pass = System.get_env("TENANT_DATABASE_PASSWORD", "postgres")

  # Create the demo tenant shard
  {:ok, shard} =
    %Shard{}
    |> Shard.changeset(%{
      name: "shard-demo",
      database_url: "postgres://#{db_user}:#{db_pass}@#{db_host}:5432/murtaugh_tenant_demo",
      database_name: "murtaugh_tenant_demo",
      host: db_host,
      port: 5432,
      pool_size: 10,
      status: "active",
      retention_days: 90
    })
    |> Repo.insert()

  # Create root org node
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
  {:ok, demo} =
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
  {:ok, admin} =
    %User{}
    |> User.registration_changeset(%{
      email: "admin@murtaugh.local",
      name: "Murtaugh Admin",
      password: "murtaugh",
      is_superadmin: true
    })
    |> Repo.insert()

  # Create a dev enrollment token for the sim-agent
  {:ok, _token} =
    %EnrollmentToken{}
    |> EnrollmentToken.changeset(%{
      org_node_id: demo.id,
      # Stored hashed; agents present the plaintext "dev-enroll-token-riggs-sim".
      token: EnrollmentToken.hash_token("dev-enroll-token-riggs-sim"),
      label: "Dev Sim Agent Token",
      created_by: admin.id
    })
    |> Repo.insert()

  IO.puts("Seeded: root node, demo account (shard-demo), superadmin, enrollment token")
end
