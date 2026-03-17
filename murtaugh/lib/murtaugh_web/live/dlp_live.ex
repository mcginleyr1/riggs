defmodule MurtaughWeb.DlpLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  alias Murtaugh.Dlp
  alias MurtaughWeb.Presenters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "dlp")
    end

    shard = socket.assigns[:current_shard]
    {events, blocks_today, alerts_today, top_domain} = load_dlp_data(shard)

    socket =
      socket
      |> assign(:page_title, "DLP")
      |> assign(:blocks_today, blocks_today)
      |> assign(:alerts_today, alerts_today)
      |> assign(:top_domain, top_domain)
      |> assign(:total_agents_blocked, 0)
      |> assign(:recent_events, events)

    {:ok, socket}
  end

  @impl true
  def handle_info({:dlp_event, event}, socket) do
    events = [Presenters.present_dlp_event(event) | Enum.take(socket.assigns.recent_events, 19)]

    socket =
      socket
      |> update(:blocks_today, &(&1 + 1))
      |> assign(:recent_events, events)

    {:noreply, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  defp load_dlp_data(nil), do: {placeholder_dlp_events(), 23, 5, "paste.ee"}

  defp load_dlp_data(shard) do
    events = shard |> Dlp.list_events(limit: 20) |> Enum.map(&Presenters.present_dlp_event/1)
    blocks = Enum.count(events, &(&1.action == "block"))
    alerts = Enum.count(events, &(&1.action == "alert"))
    top = events |> Enum.frequencies_by(& &1.domain) |> Enum.max_by(&elem(&1, 1), fn -> {"none", 0} end) |> elem(0)
    {events, blocks, alerts, top}
  rescue
    _ -> {placeholder_dlp_events(), 0, 0, "none"}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-white">Data Loss Prevention</h1>
        <.link navigate={~p"/orgs/#{@org_slug}/dlp/policies"} class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg">
          Manage Policies
        </.link>
      </div>

      <%!-- Summary cards --%>
      <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
        <.stat_card label="Blocks Today" value={to_string(@blocks_today)} trend={:down} trend_value="-4" />
        <.stat_card label="Alerts Today" value={to_string(@alerts_today)} />
        <.stat_card label="Top Blocked Domain" value={@top_domain} />
        <.stat_card label="Agents with Blocks" value={to_string(@total_agents_blocked)} />
      </div>

      <%!-- Recent DLP events --%>
      <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Recent DLP Events</h2>
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-gray-400 border-b border-gray-700">
                <th class="text-left py-2 px-4 font-medium">Time</th>
                <th class="text-left py-2 px-4 font-medium">Action</th>
                <th class="text-left py-2 px-4 font-medium">Domain</th>
                <th class="text-left py-2 px-4 font-medium">Process</th>
                <th class="text-left py-2 px-4 font-medium">Agent</th>
                <th class="text-left py-2 px-4 font-medium">Policy</th>
                <th class="text-left py-2 px-4 font-medium">File Type</th>
              </tr>
            </thead>
            <tbody>
              <tr :for={event <- @recent_events} class="border-b border-gray-700/50 hover:bg-gray-700/30">
                <td class="py-2 px-4 text-gray-400">{event.time}</td>
                <td class="py-2 px-4">
                  <span class={[
                    "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border",
                    event.action == "block" && "bg-red-900/60 border-red-700 text-red-300",
                    event.action == "alert" && "bg-yellow-900/60 border-yellow-700 text-yellow-300"
                  ]}>
                    {event.action}
                  </span>
                </td>
                <td class="py-2 px-4 text-gray-200">{event.domain}</td>
                <td class="py-2 px-4 text-gray-300 font-mono text-xs">{event.process}</td>
                <td class="py-2 px-4">
                  <.link navigate={~p"/orgs/#{@org_slug}/agents/#{event.agent_id}"} class="text-blue-400 hover:text-blue-300">
                    {event.agent}
                  </.link>
                </td>
                <td class="py-2 px-4 text-gray-300">{event.policy}</td>
                <td class="py-2 px-4 text-gray-400">{event.file_type}</td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """
  end

  defp placeholder_dlp_events do
    [
      %{id: "d1", time: "5m ago", action: "block", domain: "paste.ee", process: "chrome.exe", agent: "WS-NYC-042", agent_id: "a1", policy: "No Paste Sites", file_type: "text/plain"},
      %{id: "d2", time: "12m ago", action: "block", domain: "dropbox.com", process: "firefox.exe", agent: "WS-SF-019", agent_id: "a2", policy: "No Cloud Storage", file_type: "application/zip"},
      %{id: "d3", time: "28m ago", action: "alert", domain: "drive.google.com", process: "chrome.exe", agent: "WS-LON-003", agent_id: "a3", policy: "Monitor Cloud Storage", file_type: "application/pdf"},
      %{id: "d4", time: "44m ago", action: "block", domain: "mega.nz", process: "edge.exe", agent: "SRV-NYC-001", agent_id: "a4", policy: "No Cloud Storage", file_type: "application/octet-stream"},
      %{id: "d5", time: "1h ago", action: "block", domain: "anonfiles.com", process: "curl", agent: "WS-NYC-017", agent_id: "a5", policy: "No Paste Sites", file_type: "text/plain"},
      %{id: "d6", time: "1h ago", action: "alert", domain: "slack.com", process: "slack.exe", agent: "WS-SF-022", agent_id: "a6", policy: "Monitor Messaging", file_type: "image/png"},
      %{id: "d7", time: "2h ago", action: "block", domain: "transfer.sh", process: "wget", agent: "SRV-LON-002", agent_id: "a7", policy: "No Paste Sites", file_type: "application/gzip"},
      %{id: "d8", time: "3h ago", action: "block", domain: "paste.ee", process: "python3", agent: "WS-NYC-055", agent_id: "a8", policy: "No Paste Sites", file_type: "text/plain"}
    ]
  end
end
