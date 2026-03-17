defmodule MurtaughWeb.AgentDetailLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "agent:#{id}")
    end

    agent = placeholder_agent(id)

    socket =
      socket
      |> assign(:page_title, agent.hostname)
      |> assign(:agent, agent)
      |> assign(:recent_events, placeholder_events())
      |> assign(:active_threats, placeholder_threats())

    {:ok, socket}
  end

  @impl true
  def handle_info({:heartbeat, _health}, socket), do: {:noreply, socket}
  def handle_info({:event, _event}, socket), do: {:noreply, socket}
  def handle_info({:command_ack, _ack}, socket), do: {:noreply, socket}
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <%!-- Header --%>
      <div class="flex items-start justify-between">
        <div>
          <div class="flex items-center gap-3 mb-1">
            <.link navigate={~p"/orgs/#{@org_slug}/agents"} class="text-gray-400 hover:text-gray-200">
              <span class="hero-arrow-left size-5" /> Back
            </.link>
          </div>
          <div class="flex items-center gap-3">
            <h1 class="text-2xl font-bold text-white">{@agent.hostname}</h1>
            <.status_dot status={@agent.status} />
          </div>
          <p class="text-gray-400 mt-1">{@agent.os} -- Riggs v{@agent.version}</p>
        </div>
        <div class="flex gap-2">
          <button class="px-4 py-2 bg-orange-700 hover:bg-orange-600 text-white text-sm rounded-lg">
            Contain
          </button>
          <button class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-lg">
            Push Config
          </button>
          <button class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-lg">
            Trigger Scan
          </button>
        </div>
      </div>

      <%!-- Health panel --%>
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        <.stat_card label="Last Heartbeat" value={@agent.last_heartbeat} />
        <.stat_card label="Active Threats" value={to_string(length(@active_threats))} />
        <.stat_card label="Pipeline Latency" value="12ms" />
        <.stat_card label="Uptime" value="14d 6h" />
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <%!-- Active threats --%>
        <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <h2 class="text-lg font-semibold text-white mb-4">Active Threats</h2>
          <div :if={@active_threats == []} class="text-gray-500 text-sm py-4 text-center">
            No active threats
          </div>
          <div class="space-y-2">
            <div :for={threat <- @active_threats} class="flex items-center justify-between p-3 bg-gray-900 rounded-lg">
              <div>
                <p class="text-sm font-medium text-gray-200">{threat.process}</p>
                <p class="text-xs text-gray-400">{threat.summary}</p>
              </div>
              <.threat_badge level={threat.level} />
            </div>
          </div>
        </div>

        <%!-- Recent events --%>
        <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <h2 class="text-lg font-semibold text-white mb-4">Recent Events</h2>
          <div class="space-y-2">
            <div :for={event <- @recent_events} class="flex items-center gap-3 p-3 bg-gray-900 rounded-lg">
              <.severity_badge severity={event.severity} />
              <div class="flex-1 min-w-0">
                <p class="text-sm text-gray-200 truncate">{event.description}</p>
                <p class="text-xs text-gray-500">{event.time}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp placeholder_agent(id) do
    %{
      id: id,
      hostname: "WS-NYC-042",
      os: "Windows 11 Pro 23H2",
      status: :online,
      last_heartbeat: "30s ago",
      version: "0.4.2",
      ip: "10.0.1.42",
      enrolled_at: "2026-02-15"
    }
  end

  defp placeholder_threats do
    [
      %{id: "t1", level: :malicious, process: "powershell.exe", summary: "Encoded command execution"},
      %{id: "t2", level: :suspicious, process: "cmd.exe", summary: "Unusual child process chain"}
    ]
  end

  defp placeholder_events do
    [
      %{severity: :high, description: "Outbound TCP to 185.220.101.42:443", time: "30s ago"},
      %{severity: :medium, description: "powershell.exe spawned by explorer.exe", time: "32s ago"},
      %{severity: :low, description: "File read: C:\\Users\\admin\\payload.ps1", time: "33s ago"},
      %{severity: :info, description: "DNS query: update-service.xyz", time: "34s ago"},
      %{severity: :high, description: "Registry persistence key set", time: "35s ago"}
    ]
  end
end
