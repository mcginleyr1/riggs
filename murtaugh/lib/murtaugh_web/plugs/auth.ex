defmodule MurtaughWeb.Plugs.Auth do
  @moduledoc """
  Fetches current_user from session and assigns it to the connection.

  Looks up the real user by the session's :user_id. A missing or stale
  session id resolves to nil (RequireAuth then redirects to /login).
  """
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    user =
      conn
      |> get_session(:user_id)
      |> Murtaugh.Accounts.get_user()

    assign(conn, :current_user, user)
  end
end

defmodule MurtaughWeb.Plugs.RequireAuth do
  @moduledoc """
  Redirects to /login when there is no authenticated user on the connection.
  """
  import Plug.Conn
  import Phoenix.Controller, only: [redirect: 2, put_flash: 3]

  def init(opts), do: opts

  def call(conn, _opts) do
    if conn.assigns[:current_user] do
      conn
    else
      conn
      |> put_flash(:error, "You must log in to access this page.")
      |> redirect(to: "/login")
      |> halt()
    end
  end
end
