defmodule MurtaughWeb.Plugs.Auth do
  @moduledoc """
  Fetches current_user from session and assigns it to the connection.

  For now this uses a placeholder user map. When the Users context is ready,
  this will look up a real user by session token.
  """
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    user_id = get_session(conn, :user_id)

    if user_id do
      # Placeholder: in production this calls Murtaugh.Accounts.get_user/1
      user = %{id: user_id, email: "operator@riggs.local", name: "Operator", role: :admin}
      assign(conn, :current_user, user)
    else
      assign(conn, :current_user, nil)
    end
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
