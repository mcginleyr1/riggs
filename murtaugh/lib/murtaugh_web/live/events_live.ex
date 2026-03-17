defmodule MurtaughWeb.EventsLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  alias Murtaugh.Detection
  alias MurtaughWeb.Presenters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "events")
    end

    shard = socket.assigns[:current_shard]

    socket =
      socket
      |> assign(:page_title, "Events")
      |> assign(:events, load_events(shard))
      |> assign(:search, "")
      |> assign(:filter_type, "all")
      |> assign(:filter_severity, "all")
      |> assign(:filter_time, "24h")
      |> assign(:expanded_id, nil)
      |> assign(:page, 1)
      |> assign(:total_pages, 1)

    {:ok, socket}
  end

  defp load_events(nil), do: placeholder_events()

  defp load_events(shard) do
    shard |> Detection.list_events(limit: 100) |> Enum.map(&Presenters.present_event/1)
  rescue
    _ -> placeholder_events()
  end

  @impl true
  def handle_event("search", %{"search" => search}, socket) do
    {:noreply, assign(socket, search: search, page: 1)}
  end

  def handle_event("filter", %{"type" => type, "severity" => severity, "time" => time}, socket) do
    socket =
      socket
      |> assign(:filter_type, type)
      |> assign(:filter_severity, severity)
      |> assign(:filter_time, time)
      |> assign(:page, 1)

    {:noreply, socket}
  end

  def handle_event("toggle_expand", %{"id" => id}, socket) do
    expanded = if socket.assigns.expanded_id == id, do: nil, else: id
    {:noreply, assign(socket, :expanded_id, expanded)}
  end

  def handle_event("page", %{"page" => page}, socket) do
    {:noreply, assign(socket, :page, String.to_integer(page))}
  end

  @impl true
  def handle_info({:new_event, event}, socket) do
    events = [Presenters.present_event(event) | Enum.take(socket.assigns.events, 199)]
    {:noreply, assign(socket, :events, events)}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <h1 class="text-2xl font-bold text-white">Event Explorer</h1>

      <%!-- Search bar --%>
      <form phx-change="search" class="flex gap-3">
        <div class="flex-1">
          <input
            type="text"
            name="search"
            value={@search}
            placeholder="Search process name, path, domain, command line..."
            class="w-full px-4 py-2.5 bg-gray-800 border border-gray-700 rounded-lg text-white placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            phx-debounce="300"
          />
        </div>
      </form>

      <%!-- Filter bar --%>
      <form phx-change="filter" class="flex flex-wrap items-center gap-3 bg-gray-800 border border-gray-700 rounded-xl p-4">
        <div>
          <label class="text-xs text-gray-400 block mb-1">Event Type</label>
          <select name="type" value={@filter_type} class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option value="all">All Types</option>
            <option value="process_create">Process Create</option>
            <option value="network_connect">Network Connect</option>
            <option value="file_create">File Create</option>
            <option value="file_read">File Read</option>
            <option value="registry_set">Registry Set</option>
            <option value="dns_query">DNS Query</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">Severity</label>
          <select name="severity" value={@filter_severity} class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option value="all">All</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="info">Info</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">Time Range</label>
          <select name="time" value={@filter_time} class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option value="1h">Last Hour</option>
            <option value="24h">Last 24 Hours</option>
            <option value="7d">Last 7 Days</option>
            <option value="30d">Last 30 Days</option>
          </select>
        </div>
      </form>

      <%!-- Events table --%>
      <div class="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-gray-400 border-b border-gray-700 bg-gray-800/80">
                <th class="w-8 py-3 px-2"></th>
                <th class="text-left py-3 px-4 font-medium">Time</th>
                <th class="text-left py-3 px-4 font-medium">Type</th>
                <th class="text-left py-3 px-4 font-medium">Severity</th>
                <th class="text-left py-3 px-4 font-medium">Process</th>
                <th class="text-left py-3 px-4 font-medium">Description</th>
                <th class="text-left py-3 px-4 font-medium">Agent</th>
              </tr>
            </thead>
            <tbody>
              <%= for event <- @events do %>
                <tr
                  class="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                  phx-click="toggle_expand"
                  phx-value-id={event.id}
                >
                  <td class="py-3 px-2 text-gray-500 text-center">
                    <span class={if @expanded_id == event.id, do: "hero-chevron-down size-4", else: "hero-chevron-right size-4"} />
                  </td>
                  <td class="py-3 px-4 text-gray-400 whitespace-nowrap">{event.time}</td>
                  <td class="py-3 px-4">
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-700 text-gray-300">
                      {event.event_type}
                    </span>
                  </td>
                  <td class="py-3 px-4"><.severity_badge severity={event.severity} /></td>
                  <td class="py-3 px-4 text-gray-200 font-mono text-xs">{event.process}</td>
                  <td class="py-3 px-4 text-gray-300 max-w-xs truncate">{event.description}</td>
                  <td class="py-3 px-4 text-gray-300">{event.agent}</td>
                </tr>
                <tr :if={@expanded_id == event.id} class="bg-gray-900/50">
                  <td colspan="7" class="px-8 py-4">
                    <div class="text-xs font-mono text-gray-300 bg-gray-950 rounded-lg p-4 overflow-x-auto">
                      <pre>{Jason.encode!(event.payload, pretty: true)}</pre>
                    </div>
                  </td>
                </tr>
              <% end %>
            </tbody>
          </table>
        </div>

        <%!-- Pagination --%>
        <div class="flex items-center justify-between px-4 py-3 border-t border-gray-700">
          <div class="text-sm text-gray-400">Page {@page} of {@total_pages}</div>
          <div class="flex gap-2">
            <button
              :if={@page > 1}
              phx-click="page"
              phx-value-page={@page - 1}
              class="px-3 py-1 bg-gray-700 text-gray-300 rounded hover:bg-gray-600 text-sm"
            >
              Previous
            </button>
            <button
              :if={@page < @total_pages}
              phx-click="page"
              phx-value-page={@page + 1}
              class="px-3 py-1 bg-gray-700 text-gray-300 rounded hover:bg-gray-600 text-sm"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp placeholder_events do
    [
      %{id: "e1", time: "09:58:05", event_type: "registry_set", severity: :critical, process: "powershell.exe", description: "Set persistence key in HKLM\\...\\Run", agent: "WS-NYC-042",
        payload: %{key: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", value: "beacon.dll", pid: 4832}},
      %{id: "e2", time: "09:58:03", event_type: "file_create", severity: :high, process: "powershell.exe", description: "Created C:\\Windows\\Temp\\beacon.dll", agent: "WS-NYC-042",
        payload: %{path: "C:\\Windows\\Temp\\beacon.dll", size: 245760, sha256: "a1b2c3d4..."}},
      %{id: "e3", time: "09:58:01", event_type: "network_connect", severity: :high, process: "powershell.exe", description: "Outbound TCP to 185.220.101.42:443", agent: "WS-NYC-042",
        payload: %{dst_ip: "185.220.101.42", dst_port: 443, protocol: "tcp", bytes_sent: 1024}},
      %{id: "e4", time: "09:58:00", event_type: "dns_query", severity: :medium, process: "powershell.exe", description: "Resolved update-service.xyz", agent: "WS-NYC-042",
        payload: %{domain: "update-service.xyz", answer: "185.220.101.42", query_type: "A"}},
      %{id: "e5", time: "09:57:59", event_type: "file_read", severity: :low, process: "powershell.exe", description: "Read C:\\Users\\admin\\payload.ps1", agent: "WS-NYC-042",
        payload: %{path: "C:\\Users\\admin\\payload.ps1", size: 4096}},
      %{id: "e6", time: "09:57:58", event_type: "process_create", severity: :medium, process: "powershell.exe", description: "powershell.exe spawned by explorer.exe", agent: "WS-NYC-042",
        payload: %{pid: 4832, ppid: 1204, cmdline: "powershell.exe -enc aQBlAHgA...", user: "CORP\\admin"}},
      %{id: "e7", time: "09:55:12", event_type: "network_connect", severity: :info, process: "svchost.exe", description: "NTP sync to time.windows.com", agent: "WS-NYC-042",
        payload: %{dst_ip: "20.43.94.199", dst_port: 123, protocol: "udp"}},
      %{id: "e8", time: "09:54:01", event_type: "process_create", severity: :info, process: "notepad.exe", description: "notepad.exe spawned by explorer.exe", agent: "WS-NYC-042",
        payload: %{pid: 5120, ppid: 1204, cmdline: "notepad.exe", user: "CORP\\admin"}}
    ]
  end
end
