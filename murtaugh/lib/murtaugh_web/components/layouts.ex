defmodule MurtaughWeb.Layouts do
  @moduledoc """
  Layout components for Murtaugh.

  Provides the root HTML shell, the main app layout with sidebar navigation,
  and a minimal auth layout for the login page.
  """
  use MurtaughWeb, :html

  embed_templates "layouts/*"

  attr :flash, :map, required: true, doc: "the map of flash messages"

  attr :current_scope, :map,
    default: nil,
    doc: "the current scope"

  slot :inner_block, required: true

  def app(assigns) do
    # Build org_slug from socket assigns if available, fall back to "default"
    org_slug = assigns[:org_slug] || assigns[:current_org][:slug] || "default"
    assigns = assign(assigns, :org_slug, org_slug)

    ~H"""
    <div class="flex h-screen overflow-hidden bg-gray-950">
      <%!-- Sidebar --%>
      <aside class="w-64 flex-shrink-0 bg-gray-900 border-r border-gray-800 flex flex-col">
        <%!-- Logo --%>
        <div class="h-16 flex items-center px-6 border-b border-gray-800">
          <.link navigate={~p"/orgs/#{@org_slug}"} class="flex items-center gap-3">
            <div class="w-8 h-8 bg-blue-600 rounded-lg flex items-center justify-center">
              <span class="text-white font-bold text-sm">M</span>
            </div>
            <span class="text-lg font-bold text-white tracking-tight">Murtaugh</span>
          </.link>
        </div>

        <%!-- Navigation --%>
        <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
          <.nav_link href={~p"/orgs/#{@org_slug}"} icon="hero-squares-2x2" label="Dashboard" />
          <.nav_link href={~p"/orgs/#{@org_slug}/threats"} icon="hero-shield-exclamation" label="Threats" />
          <.nav_link href={~p"/orgs/#{@org_slug}/agents"} icon="hero-server-stack" label="Agents" />
          <.nav_link href={~p"/orgs/#{@org_slug}/events"} icon="hero-queue-list" label="Events" />
          <.nav_link href={~p"/orgs/#{@org_slug}/dlp"} icon="hero-lock-closed" label="DLP" />

          <div class="pt-4 mt-4 border-t border-gray-800">
            <.nav_link href={~p"/orgs/#{@org_slug}/settings"} icon="hero-cog-6-tooth" label="Settings" />
          </div>
        </nav>

        <%!-- Sidebar footer --%>
        <div class="p-4 border-t border-gray-800">
          <div class="text-xs text-gray-500">Riggs Endpoint Protection</div>
          <div class="text-xs text-gray-600 mt-0.5">v0.1.0</div>
        </div>
      </aside>

      <%!-- Main content area --%>
      <div class="flex-1 flex flex-col overflow-hidden">
        <%!-- Top bar --%>
        <header class="h-16 flex items-center justify-between px-6 bg-gray-900 border-b border-gray-800 flex-shrink-0">
          <div class="flex items-center gap-3">
            <%!-- Org selector --%>
            <div class="flex items-center gap-2 bg-gray-800 border border-gray-700 rounded-lg px-3 py-1.5">
              <span class="hero-building-office-2 size-4 text-gray-400" />
              <span class="text-sm text-gray-200 font-medium">
                {assigns[:current_org][:name] || "Default Org"}
              </span>
              <span class="hero-chevron-down size-3 text-gray-500" />
            </div>
          </div>

          <div class="flex items-center gap-4">
            <%!-- Notifications placeholder --%>
            <button class="relative text-gray-400 hover:text-gray-200">
              <span class="hero-bell size-5" />
              <span class="absolute -top-1 -right-1 w-2 h-2 bg-red-500 rounded-full"></span>
            </button>

            <%!-- User menu --%>
            <div class="flex items-center gap-2">
              <div class="w-8 h-8 bg-gray-700 rounded-full flex items-center justify-center">
                <span class="text-sm text-gray-300 font-medium">O</span>
              </div>
              <.link href="/logout" method="delete" class="text-sm text-gray-400 hover:text-gray-200">
                Sign out
              </.link>
            </div>
          </div>
        </header>

        <%!-- Page content --%>
        <main class="flex-1 overflow-y-auto p-6">
          {render_slot(@inner_block)}
        </main>
      </div>
    </div>

    <.flash_group flash={@flash} />
    """
  end

  @doc """
  Renders a sidebar navigation link.
  """
  attr :href, :string, required: true
  attr :icon, :string, required: true
  attr :label, :string, required: true

  def nav_link(assigns) do
    ~H"""
    <.link
      navigate={@href}
      class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium text-gray-300 hover:text-white hover:bg-gray-800 transition-colors"
    >
      <span class={[@icon, "size-5"]} />
      {@label}
    </.link>
    """
  end

  @doc """
  Shows the flash group with standard titles and content.
  """
  attr :flash, :map, required: true, doc: "the map of flash messages"
  attr :id, :string, default: "flash-group", doc: "the optional id of flash container"

  def flash_group(assigns) do
    ~H"""
    <div id={@id} aria-live="polite">
      <.flash kind={:info} flash={@flash} />
      <.flash kind={:error} flash={@flash} />

      <.flash
        id="client-error"
        kind={:error}
        title={gettext("We can't find the internet")}
        phx-disconnected={show(".phx-client-error #client-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#client-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>

      <.flash
        id="server-error"
        kind={:error}
        title={gettext("Something went wrong!")}
        phx-disconnected={show(".phx-server-error #server-error") |> JS.remove_attribute("hidden")}
        phx-connected={hide("#server-error") |> JS.set_attribute({"hidden", ""})}
        hidden
      >
        {gettext("Attempting to reconnect")}
        <.icon name="hero-arrow-path" class="ml-1 size-3 motion-safe:animate-spin" />
      </.flash>
    </div>
    """
  end
end
