defmodule MurtaughWeb.AuthController do
  use MurtaughWeb, :controller

  def login_form(conn, _params) do
    render(conn, :login, error: nil, layout: {MurtaughWeb.Layouts, :auth})
  end

  def login(conn, %{"email" => email, "password" => password}) do
    # Placeholder authentication -- accepts any non-empty credentials for now.
    # When Murtaugh.Accounts exists, this will call Accounts.authenticate(email, password).
    if email != "" and password != "" do
      conn
      |> put_session(:user_id, Ecto.UUID.generate())
      |> put_flash(:info, "Welcome back.")
      |> redirect(to: "/")
    else
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
