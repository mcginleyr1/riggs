defmodule MurtaughWeb.DashboardLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "threats")
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "dlp")
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "fleet")
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "throughput")
    end

    socket =
      socket
      |> assign(:page_title, "Dashboard")
      |> assign(:agents_online, 142)
      |> assign(:agents_offline, 8)
      |> assign(:agents_degraded, 3)
      |> assign(:threats_today, 7)
      |> assign(:dlp_blocks_today, 23)
      |> assign(:dlp_alerts_today, 5)
      |> assign(:events_per_sec, 1240)
      |> assign(:recent_threats, placeholder_threats())
      |> assign(:recent_dlp_blocks, placeholder_dlp_blocks())

    {:ok, socket}
  end

  @impl true
  def handle_info({:new_threat, threat}, socket) do
    threats = [threat | Enum.take(socket.assigns.recent_threats, 9)]

    socket =
      socket
      |> update(:threats_today, &(&1 + 1))
      |> assign(:recent_threats, threats)

    {:noreply, socket}
  end

  def handle_info({:threat_updated, _threat}, socket), do: {:noreply, socket}

  def handle_info({:dlp_event, event}, socket) do
    blocks = [event | Enum.take(socket.assigns.recent_dlp_blocks, 4)]

    socket =
      socket
      |> update(:dlp_blocks_today, &(&1 + 1))
      |> assign(:recent_dlp_blocks, blocks)

    {:noreply, socket}
  end

  def handle_info({:agent_online, _agent}, socket) do
    {:noreply, update(socket, :agents_online, &(&1 + 1))}
  end

  def handle_info({:agent_offline, _agent}, socket) do
    {:noreply, update(socket, :agents_offline, &(&1 + 1))}
  end

  def handle_info({:agent_status_change, _agent}, socket), do: {:noreply, socket}

  def handle_info({:throughput_update, eps}, socket) do
    {:noreply, assign(socket, :events_per_sec, eps)}
  end

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

  defp placeholder_threats do
    [
      %{id: "t1", time: "2m ago", level: :malicious, process: "powershell.exe", agent: "WS-NYC-042"},
      %{id: "t2", time: "8m ago", level: :suspicious, process: "curl", agent: "SRV-SF-003"},
      %{id: "t3", time: "15m ago", level: :malicious, process: "mimikatz.exe", agent: "WS-NYC-017"},
      %{id: "t4", time: "22m ago", level: :suspicious, process: "python3", agent: "WS-LON-008"},
      %{id: "t5", time: "31m ago", level: :suspicious, process: "nc", agent: "SRV-NYC-001"},
      %{id: "t6", time: "45m ago", level: :malicious, process: "rundll32.exe", agent: "WS-SF-022"},
      %{id: "t7", time: "1h ago", level: :suspicious, process: "wget", agent: "SRV-LON-002"},
      %{id: "t8", time: "1h ago", level: :malicious, process: "cmd.exe", agent: "WS-NYC-055"},
      %{id: "t9", time: "2h ago", level: :suspicious, process: "bash", agent: "SRV-SF-011"},
      %{id: "t10", time: "3h ago", level: :malicious, process: "certutil.exe", agent: "WS-NYC-033"}
    ]
  end

  defp placeholder_dlp_blocks do
    [
      %{id: "d1", time: "5m ago", action: "block", domain: "paste.ee", agent: "WS-NYC-042"},
      %{id: "d2", time: "12m ago", action: "block", domain: "dropbox.com", agent: "WS-SF-019"},
      %{id: "d3", time: "28m ago", action: "alert", domain: "drive.google.com", agent: "WS-LON-003"},
      %{id: "d4", time: "44m ago", action: "block", domain: "mega.nz", agent: "SRV-NYC-001"},
      %{id: "d5", time: "1h ago", action: "block", domain: "anonfiles.com", agent: "WS-NYC-017"}
    ]
  end
end
