defmodule MurtaughWeb.AgentsLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  alias Murtaugh.Fleet
  alias MurtaughWeb.Presenters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, Murtaugh.Topics.fleet(socket.assigns.current_org.id))
    end

    shard = socket.assigns[:current_shard]

    {:ok, assign(socket,
      page_title: "Agents",
      agents: load_agents(shard),
      filter_status: "all"
    )}
  end

  @impl true
  def handle_event("filter_status", %{"status" => status}, socket) do
    {:noreply, assign(socket, :filter_status, status)}
  end

  @impl true
  def handle_info({:agent_online, agent}, socket) do
    # Upsert by id so a re-enrolling agent doesn't accumulate duplicate rows
    # (which would grow the assigns without bound).
    presented = Presenters.present_agent(agent)
    others = Enum.reject(socket.assigns.agents, &(&1.id == presented.id))
    {:noreply, assign(socket, :agents, [presented | others])}
  end

  def handle_info({:agent_offline, agent}, socket) do
    {:noreply, assign(socket, :agents, replace_agent(socket.assigns.agents, agent))}
  end

  def handle_info({:agent_status_change, agent}, socket) do
    {:noreply, assign(socket, :agents, replace_agent(socket.assigns.agents, agent))}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  defp load_agents(nil), do: placeholder_agents()

  defp load_agents(shard) do
    shard |> Fleet.list_agents(limit: 200) |> Enum.map(&Presenters.present_agent/1)
  rescue
    _ -> placeholder_agents()
  end

  defp replace_agent(agents, updated) do
    p = Presenters.present_agent(updated)
    Enum.map(agents, fn a -> if a.id == p.id, do: p, else: a end)
  end

  @impl true
  def render(assigns) do
    filtered =
      if assigns.filter_status == "all" do
        assigns.agents
      else
        status_atom = String.to_existing_atom(assigns.filter_status)
        Enum.filter(assigns.agents, &(&1.status == status_atom))
      end

    assigns = assign(assigns, :filtered_agents, filtered)

    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-white">Agents</h1>
        <div class="text-sm text-gray-400">{length(@filtered_agents)} agents</div>
      </div>

      <%!-- Status filters --%>
      <div class="flex gap-2">
        <button
          :for={status <- ["all", "online", "offline", "degraded", "contained"]}
          phx-click="filter_status"
          phx-value-status={status}
          class={"px-3 py-1.5 text-sm rounded-lg transition-colors " <> if @filter_status == status, do: "bg-blue-600 text-white", else: "bg-gray-700 text-gray-300 hover:bg-gray-600"}
        >
          {String.capitalize(status)}
        </button>
      </div>

      <%!-- Agents table --%>
      <div class="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-gray-400 border-b border-gray-700 bg-gray-800/80">
                <th class="text-left py-3 px-4 font-medium">Status</th>
                <th class="text-left py-3 px-4 font-medium">Hostname</th>
                <th class="text-left py-3 px-4 font-medium">OS</th>
                <th class="text-left py-3 px-4 font-medium">Last Heartbeat</th>
                <th class="text-left py-3 px-4 font-medium">Threats</th>
                <th class="text-left py-3 px-4 font-medium">DLP Blocks</th>
                <th class="text-left py-3 px-4 font-medium">Version</th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={agent <- @filtered_agents}
                class="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                phx-click={JS.navigate(~p"/orgs/#{@org_slug}/agents/#{agent.id}")}
              >
                <td class="py-3 px-4"><.status_dot status={agent.status} /></td>
                <td class="py-3 px-4 text-gray-200 font-medium">{agent.hostname}</td>
                <td class="py-3 px-4 text-gray-300">{agent.os}</td>
                <td class="py-3 px-4 text-gray-400">{agent.last_heartbeat}</td>
                <td class="py-3 px-4">
                  <span class={"font-medium " <> if agent.threats > 0, do: "text-red-400", else: "text-gray-400"}>
                    {agent.threats}
                  </span>
                </td>
                <td class="py-3 px-4 text-gray-300">{agent.dlp_blocks}</td>
                <td class="py-3 px-4 text-gray-400 font-mono text-xs">{agent.version}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """
  end

  defp placeholder_agents do
    [
      %{id: "a1", hostname: "WS-NYC-042", os: "Windows 11", status: :online, last_heartbeat: "30s ago", threats: 3, dlp_blocks: 1, version: "0.4.2"},
      %{id: "a2", hostname: "SRV-SF-003", os: "Ubuntu 22.04", status: :online, last_heartbeat: "15s ago", threats: 1, dlp_blocks: 0, version: "0.4.2"},
      %{id: "a3", hostname: "WS-NYC-017", os: "Windows 10", status: :online, last_heartbeat: "45s ago", threats: 2, dlp_blocks: 4, version: "0.4.1"},
      %{id: "a4", hostname: "WS-LON-008", os: "macOS 14.3", status: :degraded, last_heartbeat: "3m ago", threats: 1, dlp_blocks: 0, version: "0.4.2"},
      %{id: "a5", hostname: "SRV-NYC-001", os: "RHEL 9", status: :online, last_heartbeat: "20s ago", threats: 0, dlp_blocks: 2, version: "0.4.2"},
      %{id: "a6", hostname: "WS-SF-022", os: "Windows 11", status: :online, last_heartbeat: "10s ago", threats: 1, dlp_blocks: 0, version: "0.4.2"},
      %{id: "a7", hostname: "SRV-LON-002", os: "Debian 12", status: :offline, last_heartbeat: "2h ago", threats: 0, dlp_blocks: 0, version: "0.4.0"},
      %{id: "a8", hostname: "WS-NYC-055", os: "Windows 11", status: :online, last_heartbeat: "25s ago", threats: 1, dlp_blocks: 3, version: "0.4.2"},
      %{id: "a9", hostname: "SRV-SF-011", os: "Ubuntu 24.04", status: :contained, last_heartbeat: "1m ago", threats: 5, dlp_blocks: 0, version: "0.4.2"},
      %{id: "a10", hostname: "WS-NYC-033", os: "Windows 10", status: :offline, last_heartbeat: "5h ago", threats: 0, dlp_blocks: 0, version: "0.3.9"}
    ]
  end
end
