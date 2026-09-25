defmodule MurtaughWeb.SettingsLiveTest do
  use MurtaughWeb.ConnCase

  import Phoenix.LiveViewTest

  alias Murtaugh.{Accounts, Org, Repo, ShardManager}
  alias Murtaugh.Accounts.User
  alias Murtaugh.Fleet.EnrollmentToken
  alias Murtaugh.Org.Node

  setup do
    {:ok, _root} =
      Org.create_node(%{node_type: "root", name: "Root", slug: "root", lft: 1, rgt: 4})

    {:ok, acme} =
      Org.create_node(%{
        node_type: "account",
        name: "Acme",
        slug: "acme",
        lft: 2,
        rgt: 3,
        depth: 1
      })

    {:ok, superadmin} =
      %User{is_superadmin: true}
      |> User.registration_changeset(%{email: "su@t.test", name: "SU", password: "password123"})
      |> Repo.insert()

    {:ok, viewer} =
      Accounts.add_user_to_node(
        %{email: "viewer@t.test", name: "Viewer", password: "password123"},
        acme,
        "viewer"
      )

    %{acme: acme, superadmin: superadmin, viewer: viewer}
  end

  defp settings(conn, user) do
    {:ok, view, html} =
      conn |> init_test_session(user_id: user.id) |> live(~p"/orgs/acme/settings")

    {view, html}
  end

  test "lists real users granted on the org", %{conn: conn, superadmin: su} do
    {_view, html} = settings(conn, su)
    assert html =~ "viewer@t.test"
    refute html =~ "achen@riggs.local"
  end

  test "an admin can add a user with a role", %{conn: conn, superadmin: su, acme: acme} do
    {view, _} = settings(conn, su)

    view
    |> form("form[phx-submit=add_user]",
      user: %{name: "New", email: "new@t.test", password: "password123", role: "analyst"}
    )
    |> render_submit()

    assert {_, "analyst"} =
             Enum.find(Accounts.list_node_users(acme), fn {u, _} -> u.email == "new@t.test" end)
  end

  test "generated enrollment tokens are shown once and stored hashed", %{
    conn: conn,
    superadmin: su
  } do
    {view, _} = settings(conn, su)
    render_click(view, "switch_tab", %{"tab" => "tokens"})

    html =
      view
      |> form("form[phx-submit=create_token]", token: %{label: "laptops", uses_remaining: "5"})
      |> render_submit()

    [plaintext] = Regex.run(~r/enrl_[A-Za-z0-9_-]+/, html)
    token = Repo.get_by!(EnrollmentToken, label: "laptops")
    assert token.token == EnrollmentToken.hash_token(plaintext)
    assert token.uses_remaining == 5
  end

  test "non-admins see no management forms and their events are rejected", %{
    conn: conn,
    viewer: viewer
  } do
    {view, html} = settings(conn, viewer)
    refute html =~ "Add User"
    refute html =~ "Tenants"

    html =
      render_submit(view, "create_tenant", %{
        "tenant" => %{"name" => "X", "slug" => "x", "retention_days" => "30"}
      })

    assert html =~ "permission"
    refute Repo.get_by(Node, slug: "x")
  end

  test "a superadmin creates a provisioned tenant", %{conn: conn, superadmin: su} do
    {view, _} = settings(conn, su)
    render_click(view, "switch_tab", %{"tab" => "tenants"})

    html =
      view
      |> form("form[phx-submit=create_tenant]",
        tenant: %{name: "Globex", slug: "globex", retention_days: "30"}
      )
      |> render_submit()

    node = Repo.get_by!(Node, slug: "globex") |> Repo.preload(:tenant_shard)

    on_exit(fn ->
      ShardManager.stop_repo(node.tenant_shard.id)

      Ecto.Adapters.SQL.Sandbox.unboxed_run(Repo, fn ->
        Ecto.Adapters.SQL.query!(
          Repo,
          "DROP DATABASE IF EXISTS murtaugh_tenant_globex WITH (FORCE)"
        )
      end)
    end)

    assert html =~ "Tenant globex provisioned"
    assert node.tenant_shard.status == "active"
    assert node.tenant_shard.retention_days == 30
  end
end
