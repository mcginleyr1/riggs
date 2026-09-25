defmodule MurtaughWeb.PageControllerTest do
  use MurtaughWeb.ConnCase

  test "GET / redirects unauthenticated users to login", %{conn: conn} do
    conn = get(conn, ~p"/")
    assert redirected_to(conn) == ~p"/login"
  end

  test "org-scoped pages redirect unauthenticated users to login", %{conn: conn} do
    conn = get(conn, ~p"/orgs/any-org")
    assert redirected_to(conn) == ~p"/login"
  end
end
