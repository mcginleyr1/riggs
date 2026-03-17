defmodule MurtaughWeb.PageController do
  use MurtaughWeb, :controller

  def home(conn, _params) do
    # Redirect to the default org dashboard.
    # When multi-tenancy is wired up, this will look up the user's
    # default org or show an org picker if they belong to multiple.
    redirect(conn, to: ~p"/orgs/default")
  end
end
