defmodule MurtaughWeb.OrgHookTest do
  use MurtaughWeb.ConnCase

  import Phoenix.LiveViewTest

  alias Murtaugh.{Accounts, Org}
  alias Murtaugh.Accounts.User

  setup do
    {:ok, root} =
      Org.create_node(%{node_type: "root", name: "Root", slug: "root", lft: 1, rgt: 6})

    {:ok, acme} =
      Org.create_node(%{
        node_type: "account",
        name: "Acme",
        slug: "acme",
        lft: 2,
        rgt: 3,
        depth: 1
      })

    {:ok, other} =
      Org.create_node(%{
        node_type: "account",
        name: "Other",
        slug: "other",
        lft: 4,
        rgt: 5,
        depth: 1
      })

    {:ok, user} =
      Accounts.register_user(%{
        email: "analyst@acme.test",
        name: "Analyst",
        password: "password123"
      })

    {:ok, _} = Accounts.grant_access(user.id, acme.id, "viewer")

    %{root: root, acme: acme, other: other, user: user}
  end

  defp log_in(conn, user), do: init_test_session(conn, user_id: user.id)

  test "allows an org the user has a grant on", %{conn: conn, user: user} do
    assert {:ok, _view, _html} = live(log_in(conn, user), ~p"/orgs/acme")
  end

  test "denies an org the user has no grant on", %{conn: conn, user: user} do
    assert {:error, {:redirect, %{to: "/login"}}} = live(log_in(conn, user), ~p"/orgs/other")
  end

  test "a grant on an ancestor covers its descendants", %{conn: conn, root: root} do
    {:ok, user} =
      Accounts.register_user(%{email: "admin@root.test", name: "Root", password: "password123"})

    {:ok, _} = Accounts.grant_access(user.id, root.id, "admin")

    assert {:ok, _view, _html} = live(log_in(conn, user), ~p"/orgs/other")
  end

  test "superadmins can access every org", %{conn: conn} do
    {:ok, admin} =
      %User{is_superadmin: true}
      |> User.registration_changeset(%{
        email: "su@test.test",
        name: "SU",
        password: "password123"
      })
      |> Murtaugh.Repo.insert()

    assert {:ok, _view, _html} = live(log_in(conn, admin), ~p"/orgs/other")
  end

  test "registration cannot self-assign superadmin" do
    {:ok, user} =
      Accounts.register_user(%{
        email: "sneaky@test.test",
        name: "Sneaky",
        password: "password123",
        is_superadmin: true
      })

    refute user.is_superadmin
  end
end
