defmodule MurtaughWeb.DashboardLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  alias Murtaugh.{Detection, Dlp, Fleet}
  alias MurtaughWeb.Presenters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "threats")
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "dlp")
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "fleet")
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "throughput")
    end

    shard = socket.assigns[:current_shard]

    {agents_online, agents_offline, agents_degraded, threats_today,
     recent_threats, recent_dlp_blocks, dlp_blocks_today, events_per_sec} =
      load_dashboard_data(shard)

    {:ok, assign(socket,
      page_title: "Dashboard",
      agents_online: agents_online,
      agents_offline: agents_offline,
      agents_degraded: agents_degraded,
      threats_today: threats_today,
      dlp_blocks_today: dlp_blocks_today,
      dlp_alerts_today: 0,
      events_per_sec: events_per_sec,
      recent_threats: recent_threats,
      recent_dlp_blocks: recent_dlp_blocks
    )}
  end

  @impl true
  def handle_info({:new_threat, threat}, socket) do
    threats = [Presenters.present_threat(threat) | Enum.take(socket.assigns.recent_threats, 9)]
    {:noreply, assign(socket, threats_today: socket.assigns.threats_today + 1, recent_threats: threats)}
  end

  def handle_info({:threat_updated, _threat}, socket), do: {:noreply, socket}

  def handle_info({:dlp_event, event}, socket) do
    blocks = [Presenters.present_dlp_event(event) | Enum.take(socket.assigns.recent_dlp_blocks, 4)]
    {:noreply, assign(socket, dlp_blocks_today: socket.assigns.dlp_blocks_today + 1, recent_dlp_blocks: blocks)}
  end

  def handle_info({:agent_online, _agent}, socket),
    do: {:noreply, update(socket, :agents_online, &(&1 + 1))}

  def handle_info({:agent_offline, _agent}, socket),
    do: {:noreply, update(socket, :agents_offline, &(&1 + 1))}

  def handle_info({:agent_status_change, _agent}, socket), do: {:noreply, socket}
  def handle_info({:throughput_update, eps}, socket), do: {:noreply, assign(socket, :events_per_sec, eps)}
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <h1 class="text-2xl font-bold text-white">Dashboard</h1>

      <%!-- Fleet health summary --%>
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <.stat_card label="Online Agents" value={to_string(@agents_online)} trend={:up} trend_value="+3" />
        <.stat_card label="Offline Agents" value={to_string(@agents_offline)} />
        <.stat_card label="Threats Today" value={to_string(@threats_today)} trend={:down} trend_value="-2" />
        <.stat_card label="DLP Blocks" value={to_string(@dlp_blocks_today)} />
        <.stat_card label="Events/sec" value={to_string(@events_per_sec)} />
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <%!-- Recent threats --%>
        <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-white">Recent Threats</h2>
            <.link navigate={~p"/orgs/#{@org_slug}/threats"} class="text-sm text-blue-400 hover:text-blue-300">
              View all
            </.link>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="text-gray-400 border-b border-gray-700">
                  <th class="text-left py-2 px-2 font-medium">Time</th>
                  <th class="text-left py-2 px-2 font-medium">Level</th>
                  <th class="text-left py-2 px-2 font-medium">Process</th>
                  <th class="text-left py-2 px-2 font-medium">Agent</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={threat <- @recent_threats} class="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td class="py-2 px-2 text-gray-400">{threat.time}</td>
                  <td class="py-2 px-2"><.threat_badge level={threat.level} /></td>
                  <td class="py-2 px-2 text-gray-200">{threat.process}</td>
                  <td class="py-2 px-2 text-gray-300">{threat.agent}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <%!-- Recent DLP blocks --%>
        <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <div class="flex items-center justify-between mb-4">
            <h2 class="text-lg font-semibold text-white">Recent DLP Blocks</h2>
            <.link navigate={~p"/orgs/#{@org_slug}/dlp"} class="text-sm text-blue-400 hover:text-blue-300">
              View all
            </.link>
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="text-gray-400 border-b border-gray-700">
                  <th class="text-left py-2 px-2 font-medium">Time</th>
                  <th class="text-left py-2 px-2 font-medium">Action</th>
                  <th class="text-left py-2 px-2 font-medium">Domain</th>
                  <th class="text-left py-2 px-2 font-medium">Agent</th>
                </tr>
              </thead>
              <tbody>
                <tr :for={block <- @recent_dlp_blocks} class="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td class="py-2 px-2 text-gray-400">{block.time}</td>
                  <td class="py-2 px-2">
                    <span class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-red-900/60 border border-red-700 text-red-300">
                      {block.action}
                    </span>
                  </td>
                  <td class="py-2 px-2 text-gray-200">{block.domain}</td>
                  <td class="py-2 px-2 text-gray-300">{block.agent}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp load_dashboard_data(nil) do
    {142, 8, 3, 7, placeholder_threats(), placeholder_dlp_blocks(), 23, 1240}
  end

  defp load_dashboard_data(shard) do
    status_counts = Fleet.count_by_status(shard)
    threats_today = Detection.count_threats_today(shard)
    recent_threats = shard |> Detection.list_threats(limit: 10) |> Enum.map(&Presenters.present_threat/1)
    recent_dlp = shard |> Dlp.recent_blocks(limit: 5) |> Enum.map(&Presenters.present_dlp_event/1)
    dlp_blocks = shard |> Dlp.list_events(action: "block") |> length()

    {
      Map.get(status_counts, "online", 0),
      Map.get(status_counts, "offline", 0),
      Map.get(status_counts, "degraded", 0),
      threats_today,
      recent_threats,
      recent_dlp,
      dlp_blocks,
      0
    }
  rescue
    _ -> {0, 0, 0, 0, [], [], 0, 0}
  end

  defp placeholder_threats do
    [
      %{id: "t1", time: "2m ago", level: :malicious, process: "powershell.exe", agent: "WS-NYC-042"},
      %{id: "t2", time: "8m ago", level: :suspicious, process: "curl", agent: "SRV-SF-003"},
      %{id: "t3", time: "15m ago", level: :malicious, process: "mimikatz.exe", agent: "WS-NYC-017"}
    ]
  end

  defp placeholder_dlp_blocks do
    [
      %{id: "d1", time: "5m ago", action: "block", domain: "paste.ee", agent: "WS-NYC-042"},
      %{id: "d2", time: "12m ago", action: "block", domain: "dropbox.com", agent: "WS-SF-019"},
      %{id: "d3", time: "28m ago", action: "alert", domain: "drive.google.com", agent: "WS-LON-003"}
    ]
  end
end
