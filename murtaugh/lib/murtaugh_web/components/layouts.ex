defmodule MurtaughWeb.Layouts do
  @moduledoc false
  use MurtaughWeb, :html

  embed_templates "layouts/*"

  def app(assigns) do
    org_slug = assigns[:org_slug] || "demo"
    assigns = assign(assigns, :org_slug, org_slug)

    ~H"""
    <div class="flex h-screen overflow-hidden" style="background: #060810;">

      <%!-- ── Sidebar ─────────────────────────────────────────────────── --%>
      <aside class="w-52 flex-shrink-0 flex flex-col" style="background: #07090f; border-right: 1px solid rgba(255,255,255,0.05);">

        <%!-- Wordmark --%>
        <div class="px-5 h-14 flex items-center" style="border-bottom: 1px solid rgba(255,255,255,0.05);">
          <div class="flex items-center gap-2.5">
            <div class="w-6 h-6 rounded flex items-center justify-center" style="background: rgba(239,68,68,0.15); border: 1px solid rgba(239,68,68,0.3);">
              <svg class="w-3 h-3" style="color: #f87171;" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2.5" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
              </svg>
            </div>
            <span style="font-family: 'Barlow Condensed', sans-serif; font-weight: 700; font-size: 0.85rem; letter-spacing: 0.18em; text-transform: uppercase; color: rgba(255,255,255,0.85);">Murtaugh</span>
          </div>
        </div>

        <%!-- Org pill --%>
        <div class="mx-3 my-3 px-3 py-2 rounded" style="background: rgba(255,255,255,0.04);">
          <p style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; text-transform: uppercase; letter-spacing: 0.1em; color: rgba(255,255,255,0.3); margin-bottom: 2px;">workspace</p>
          <p style="font-size: 12px; font-weight: 500; color: rgba(255,255,255,0.7);" class="capitalize">{String.replace(@org_slug, "-", " ")}</p>
        </div>

        <%!-- Nav --%>
        <nav class="flex-1 px-2 py-1 space-y-0.5">
          <.nav_link href={~p"/orgs/#{@org_slug}/"} label="Dashboard">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.75" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" /></svg>
          </.nav_link>
          <.nav_link href={~p"/orgs/#{@org_slug}/threats"} label="Threats">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.75" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" /></svg>
          </.nav_link>
          <.nav_link href={~p"/orgs/#{@org_slug}/agents"} label="Agents">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.75" d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" /></svg>
          </.nav_link>
          <.nav_link href={~p"/orgs/#{@org_slug}/events"} label="Events">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.75" d="M4 6h16M4 12h16M4 18h7" /></svg>
          </.nav_link>
          <.nav_link href={~p"/orgs/#{@org_slug}/dlp"} label="DLP">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.75" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" /></svg>
          </.nav_link>

          <div class="pt-4 pb-1 px-3">
            <div style="height: 1px; background: rgba(255,255,255,0.05);"></div>
          </div>

          <.nav_link href={~p"/orgs/#{@org_slug}/settings"} label="Settings">
            <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.75" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" /><path stroke-linecap="round" stroke-linejoin="round" stroke-width="1.75" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" /></svg>
          </.nav_link>
        </nav>

        <%!-- Live status --%>
        <div class="px-4 py-4" style="border-top: 1px solid rgba(255,255,255,0.05);">
          <div class="flex items-center gap-2">
            <span class="relative flex h-1.5 w-1.5">
              <span class="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75" style="background: #4ade80;"></span>
              <span class="relative inline-flex rounded-full h-1.5 w-1.5" style="background: #22c55e;"></span>
            </span>
            <span style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; color: rgba(255,255,255,0.25); letter-spacing: 0.05em;">live</span>
          </div>
        </div>
      </aside>

      <%!-- ── Main ──────────────────────────────────────────────────────── --%>
      <div class="flex-1 flex flex-col min-w-0 overflow-hidden">

        <%!-- Topbar --%>
        <header class="flex-shrink-0 h-14 flex items-center justify-between px-6" style="background: #07090f; border-bottom: 1px solid rgba(255,255,255,0.05);">
          <span style="font-family: 'Barlow Condensed', sans-serif; font-weight: 600; font-size: 0.9rem; letter-spacing: 0.08em; text-transform: uppercase; color: rgba(255,255,255,0.5);">
            {assigns[:page_title] || "Console"}
          </span>
          <div class="flex items-center gap-5">
            <span style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.3);">
              {assigns[:current_user] |> then(fn u -> if is_map(u), do: Map.get(u, :email, ""), else: "" end)}
            </span>
            <.link href={~p"/logout"} method="delete" style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.2);" class="hover:text-white/50 transition-colors">
              exit
            </.link>
          </div>
        </header>

        <main class="flex-1 overflow-y-auto p-6">
          {@inner_content}
        </main>
      </div>
    </div>

    <.flash_group flash={@flash} />
    """
  end

  attr :href, :string, required: true
  attr :label, :string, required: true
  slot :inner_block, required: true

  def nav_link(assigns) do
    ~H"""
    <.link
      navigate={@href}
      class="flex items-center gap-2.5 px-3 py-2 rounded text-sm transition-colors group"
      style="color: rgba(255,255,255,0.4);"
    >
      <span style="color: rgba(255,255,255,0.3);" class="group-hover:text-white/60 transition-colors">
        {render_slot(@inner_block)}
      </span>
      <span class="group-hover:text-white/80 transition-colors" style="font-size: 13px; font-weight: 500;">
        {@label}
      </span>
    </.link>
    """
  end

  attr :flash, :map, required: true
  attr :id, :string, default: "flash-group"

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
