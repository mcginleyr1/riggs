defmodule MurtaughWeb.AuthController do
  use MurtaughWeb, :controller

  def login_form(conn, _params) do
    render(conn, :login, error: nil, layout: {MurtaughWeb.Layouts, :auth})
  end

  def login(conn, %{"email" => email, "password" => password}) do
    case Murtaugh.Accounts.authenticate_user(email, password) do
      {:ok, user} ->
        conn
        |> configure_session(renew: true)
        |> put_session(:user_id, user.id)
        |> put_flash(:info, "Welcome back.")
        |> redirect(to: "/")

      {:error, _reason} ->
        render(conn, :login,
          error: "Invalid email or password.",
          layout: {MurtaughWeb.Layouts, :auth}
        )
    end
  end

  def logout(conn, _params) do
    conn
    |> configure_session(drop: true)
    |> put_flash(:info, "Logged out.")
    |> redirect(to: "/login")
  end
end
