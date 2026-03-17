defmodule MurtaughWeb.Router do
  use MurtaughWeb, :router

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {MurtaughWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug MurtaughWeb.Plugs.Auth
  end

  pipeline :require_auth do
    plug MurtaughWeb.Plugs.RequireAuth
  end

  pipeline :api do
    plug :accepts, ["json"]
  end

  # Public routes (login)
  scope "/", MurtaughWeb do
    pipe_through :browser

    get "/login", AuthController, :login_form
    post "/login", AuthController, :login
    delete "/logout", AuthController, :logout
  end

  # Root redirect -- sends authenticated users to default org
  scope "/", MurtaughWeb do
    pipe_through [:browser, :require_auth]

    get "/", PageController, :home
  end

  # Org-scoped LiveView routes
  scope "/orgs/:org_slug", MurtaughWeb do
    pipe_through [:browser, :require_auth]

    live_session :org_scoped,
      on_mount: [{MurtaughWeb.OrgHook, :default}],
      layout: {MurtaughWeb.Layouts, :app} do
      live "/", DashboardLive, :index
      live "/threats", ThreatsLive, :index
      live "/threats/:id", ThreatDetailLive, :show
      live "/agents", AgentsLive, :index
      live "/agents/:id", AgentDetailLive, :show
      live "/events", EventsLive, :index
      live "/dlp", DlpLive, :index
      live "/dlp/policies", DlpPoliciesLive, :index
      live "/settings", SettingsLive, :index
    end
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:murtaugh, :dev_routes) do
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: MurtaughWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
