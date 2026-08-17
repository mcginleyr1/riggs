defmodule MurtaughWeb.EventsLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  alias Murtaugh.Detection
  alias MurtaughWeb.Presenters

  @per_page 25

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "events")
    end

    socket =
      socket
      |> assign(
        page_title: "Events",
        search: "",
        filter_type: "all",
        filter_severity: "all",
        filter_time: "24h",
        expanded_id: nil,
        page: 1,
        total_pages: 1,
        total_count: 0
      )
      |> reload()

    {:ok, socket}
  end

  @impl true
  def handle_event("search", %{"search" => search}, socket) do
    {:noreply, socket |> assign(search: search, page: 1) |> reload()}
  end

  def handle_event("filter", %{"type" => type, "severity" => severity, "time" => time}, socket) do
    {:noreply,
     socket
     |> assign(filter_type: type, filter_severity: severity, filter_time: time, page: 1)
     |> reload()}
  end

  def handle_event("toggle_expand", %{"id" => id}, socket) do
    expanded = if socket.assigns.expanded_id == id, do: nil, else: id
    {:noreply, assign(socket, :expanded_id, expanded)}
  end

  def handle_event("page", %{"page" => page}, socket) do
    {:noreply, socket |> assign(:page, String.to_integer(page)) |> reload()}
  end

  @impl true
  def handle_info({:new_event, _event}, socket) do
    # New telemetry only appears on the first page (newest-first); refresh there
    # so counts and the visible page stay consistent without re-querying on every
    # event while the operator is paging through history.
    socket = if socket.assigns.page == 1, do: reload(socket), else: socket
    {:noreply, socket}
  end

  def handle_info(_msg, socket), do: {:noreply, socket}

  # -- Data loading --

  defp reload(socket) do
    opts = query_opts(socket.assigns)
    {events, total} = load_page(socket.assigns[:current_shard], opts)
    total_pages = max(1, ceil(total / @per_page))

    assign(socket, events: events, total_count: total, total_pages: total_pages)
  end

  defp query_opts(assigns) do
    [
      limit: @per_page,
      offset: (assigns.page - 1) * @per_page,
      event_type: assigns.filter_type,
      severity: assigns.filter_severity,
      search: assigns.search,
      since: since_from(assigns.filter_time)
    ]
  end

  defp load_page(nil, opts), do: placeholder_page(opts)

  defp load_page(shard, opts) do
    events = shard |> Detection.list_events(opts) |> Enum.map(&Presenters.present_event/1)
    total = Detection.count_events(shard, opts)
    {events, total}
  rescue
    _ -> placeholder_page(opts)
  end

  defp since_from(range) do
    now = DateTime.utc_now()

    case range do
      "1h" -> DateTime.add(now, -3_600, :second)
      "24h" -> DateTime.add(now, -86_400, :second)
      "7d" -> DateTime.add(now, -604_800, :second)
      "30d" -> DateTime.add(now, -2_592_000, :second)
      _ -> nil
    end
  end

  # In-memory equivalent of the DB filters for the no-shard/dev fallback so the
  # controls behave identically against placeholder data.
  defp placeholder_page(opts) do
    filtered = filter_placeholders(placeholder_events(), opts)
    offset = Keyword.get(opts, :offset, 0)
    limit = Keyword.get(opts, :limit, @per_page)
    {filtered |> Enum.drop(offset) |> Enum.take(limit), length(filtered)}
  end

  defp filter_placeholders(events, opts) do
    type = Keyword.get(opts, :event_type)
    sev = Keyword.get(opts, :severity)
    search = opts |> Keyword.get(:search) |> to_string() |> String.downcase()

    Enum.filter(events, fn e ->
      type_ok?(type, e) and severity_ok?(sev, e) and search_ok?(search, e)
    end)
  end

  defp type_ok?(type, _e) when type in [nil, "", "all"], do: true
  defp type_ok?(type, e), do: e.event_type == type

  defp severity_ok?(sev, _e) when sev in [nil, "", "all"], do: true
  defp severity_ok?(sev, e), do: Atom.to_string(e.severity) == sev

  defp search_ok?("", _e), do: true

  defp search_ok?(search, e) do
    haystack = String.downcase("#{e.process} #{e.description} #{e.event_type}")
    String.contains?(haystack, search)
  end

  # -- Select option sources (also drive the sticky `selected` state) --

  defp type_options do
    [
      {"all", "All Types"},
      {"process_create", "Process Create"},
      {"network_connect", "Network Connect"},
      {"file_create", "File Create"},
      {"file_read", "File Read"},
      {"registry_set", "Registry Set"},
      {"dns_query", "DNS Query"}
    ]
  end

  defp severity_options do
    [
      {"all", "All"},
      {"critical", "Critical"},
      {"high", "High"},
      {"medium", "Medium"},
      {"low", "Low"},
      {"info", "Info"}
    ]
  end

  defp time_options do
    [{"1h", "Last Hour"}, {"24h", "Last 24 Hours"}, {"7d", "Last 7 Days"}, {"30d", "Last 30 Days"}]
  end

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
          <select name="type" class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option :for={{val, label} <- type_options()} value={val} selected={@filter_type == val}>{label}</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">Severity</label>
          <select name="severity" class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option :for={{val, label} <- severity_options()} value={val} selected={@filter_severity == val}>{label}</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">Time Range</label>
          <select name="time" class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option :for={{val, label} <- time_options()} value={val} selected={@filter_time == val}>{label}</option>
          </select>
        </div>
        <div class="ml-auto text-xs text-gray-400 self-end pb-1">
          {@total_count} event{if @total_count == 1, do: "", else: "s"}
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
              <tr :if={@events == []}>
                <td colspan="7" class="py-8 text-center text-gray-500">No events match these filters.</td>
              </tr>
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
