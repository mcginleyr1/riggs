alias Murtaugh.Repo
alias Murtaugh.Org.Node
alias Murtaugh.Accounts.User
alias Murtaugh.Fleet.EnrollmentToken

# Idempotent: only seed if no root node exists
unless Repo.get_by(Node, node_type: "root") do
  {:ok, _root} =
    %Node{}
    |> Node.changeset(%{node_type: "root", name: "Root", slug: "root", lft: 1, rgt: 2})
    |> Repo.insert()

  # Demo tenant: org node, shard and database (murtaugh_tenant_demo), provisioned
  # the same way as any other tenant.
  {:ok, %{node: demo}} =
    Murtaugh.Tenancy.create_tenant(%{
      name: "Demo Account",
      slug: "demo",
      metadata: %{"description" => "Default demo account for development"}
    })

  # Create superadmin user
  {:ok, admin} =
    %User{is_superadmin: true}
    |> User.registration_changeset(%{
      email: "admin@murtaugh.local",
      name: "Murtaugh Admin",
      password: "murtaugh"
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

  IO.puts("Seeded: root node, demo tenant (murtaugh_tenant_demo), superadmin, enrollment token")
end
