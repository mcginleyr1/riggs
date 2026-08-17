defmodule MurtaughWeb.ThreatsLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  alias Murtaugh.Detection
  alias MurtaughWeb.Presenters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, Murtaugh.Topics.threats(socket.assigns.current_org.id))
    end

    shard = socket.assigns[:current_shard]
    threats = load_threats(shard)

    {:ok, assign(socket,
      page_title: "Threats",
      threats: threats,
      filter_severity: "all",
      filter_status: "all",
      filter_time: "24h",
      sort_by: :timestamp,
      sort_dir: :desc,
      page: 1,
      total_pages: 1
    )}
  end

  defp load_threats(nil), do: placeholder_threats()

  defp load_threats(shard) do
    shard |> Detection.list_threats(limit: 100) |> Enum.map(&Presenters.present_threat/1)
  rescue
    _ -> placeholder_threats()
  end

  @impl true
  def handle_event("filter", %{"severity" => severity, "status" => status, "time" => time}, socket) do
    {:noreply, assign(socket, filter_severity: severity, filter_status: status, filter_time: time, page: 1)}
  end

  def handle_event("sort", %{"field" => field}, socket) do
    field = String.to_existing_atom(field)

    {sort_by, sort_dir} =
      if socket.assigns.sort_by == field do
        dir = if socket.assigns.sort_dir == :asc, do: :desc, else: :asc
        {field, dir}
      else
        {field, :desc}
      end

    {:noreply, assign(socket, sort_by: sort_by, sort_dir: sort_dir)}
  end

  def handle_event("page", %{"page" => page}, socket) do
    {:noreply, assign(socket, :page, String.to_integer(page))}
  end

  @impl true
  def handle_info({:new_threat, threat}, socket) do
    # Cap the retained list so a long-lived tab on a busy tenant can't grow the
    # socket's assigns without bound.
    threats = [Presenters.present_threat(threat) | Enum.take(socket.assigns.threats, 199)]
    {:noreply, assign(socket, :threats, threats)}
  end

  def handle_info({:threat_updated, _threat}, socket), do: {:noreply, socket}
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <h1 class="text-2xl font-bold text-white">Threats</h1>
        <div class="text-sm text-gray-400">{length(@threats)} threats found</div>
      </div>

      <%!-- Filter bar --%>
      <form phx-change="filter" class="flex flex-wrap items-center gap-3 bg-gray-800 border border-gray-700 rounded-xl p-4">
        <div>
          <label class="text-xs text-gray-400 block mb-1">Severity</label>
          <select name="severity" value={@filter_severity} class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option value="all">All</option>
            <option value="malicious">Malicious</option>
            <option value="suspicious">Suspicious</option>
          </select>
        </div>
        <div>
          <label class="text-xs text-gray-400 block mb-1">Status</label>
          <select name="status" value={@filter_status} class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-1.5 focus:ring-blue-500 focus:border-blue-500">
            <option value="all">All</option>
            <option value="open">Open</option>
            <option value="acknowledged">Acknowledged</option>
            <option value="resolved">Resolved</option>
            <option value="false_positive">False Positive</option>
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

      <%!-- Threats table --%>
      <div class="bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm">
            <thead>
              <tr class="text-gray-400 border-b border-gray-700 bg-gray-800/80">
                <th class="text-left py-3 px-4 font-medium cursor-pointer hover:text-gray-200" phx-click="sort" phx-value-field="timestamp">
                  Time {sort_indicator(@sort_by, @sort_dir, :timestamp)}
                </th>
                <th class="text-left py-3 px-4 font-medium cursor-pointer hover:text-gray-200" phx-click="sort" phx-value-field="level">
                  Level {sort_indicator(@sort_by, @sort_dir, :level)}
                </th>
                <th class="text-left py-3 px-4 font-medium cursor-pointer hover:text-gray-200" phx-click="sort" phx-value-field="status">
                  Status {sort_indicator(@sort_by, @sort_dir, :status)}
                </th>
                <th class="text-left py-3 px-4 font-medium">Process</th>
                <th class="text-left py-3 px-4 font-medium">Agent</th>
                <th class="text-left py-3 px-4 font-medium">Summary</th>
                <th class="text-left py-3 px-4 font-medium">Score</th>
              </tr>
            </thead>
            <tbody>
              <tr
                :for={threat <- @threats}
                class="border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer"
                phx-click={JS.navigate(~p"/orgs/#{@org_slug}/threats/#{threat.id}")}
              >
                <td class="py-3 px-4 text-gray-400">{threat.time}</td>
                <td class="py-3 px-4"><.threat_badge level={threat.level} /></td>
                <td class="py-3 px-4">
                  <span class={"inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium " <> status_class(threat.status)}>
                    {threat.status}
                  </span>
                </td>
                <td class="py-3 px-4 text-gray-200 font-mono text-xs">{threat.process}</td>
                <td class="py-3 px-4 text-gray-300">{threat.agent}</td>
                <td class="py-3 px-4 text-gray-300 max-w-xs truncate">{threat.summary}</td>
                <td class="py-3 px-4 text-gray-200">{threat.score}</td>
              </tr>
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

  defp sort_indicator(current_field, dir, field) when current_field == field do
    if dir == :asc, do: "^", else: "v"
  end

  defp sort_indicator(_current_field, _dir, _field), do: ""

  defp status_class("open"), do: "bg-red-900/60 border border-red-700 text-red-300"
  defp status_class("acknowledged"), do: "bg-yellow-900/60 border border-yellow-700 text-yellow-300"
  defp status_class("resolved"), do: "bg-green-900/60 border border-green-700 text-green-300"
  defp status_class(_), do: "bg-gray-700/60 border border-gray-600 text-gray-300"

  defp placeholder_threats do
    [
      %{id: "t1", time: "2m ago", level: :malicious, status: "open", process: "powershell.exe", agent: "WS-NYC-042", summary: "Encoded command execution with network callback", score: "0.95"},
      %{id: "t2", time: "8m ago", level: :suspicious, status: "open", process: "curl", agent: "SRV-SF-003", summary: "Unusual outbound connection to known C2 IP", score: "0.72"},
      %{id: "t3", time: "15m ago", level: :malicious, status: "acknowledged", process: "mimikatz.exe", agent: "WS-NYC-017", summary: "Credential dumping tool detected", score: "0.99"},
      %{id: "t4", time: "22m ago", level: :suspicious, status: "open", process: "python3", agent: "WS-LON-008", summary: "Script spawning reverse shell", score: "0.68"},
      %{id: "t5", time: "31m ago", level: :suspicious, status: "resolved", process: "nc", agent: "SRV-NYC-001", summary: "Netcat listener on non-standard port", score: "0.61"},
      %{id: "t6", time: "45m ago", level: :malicious, status: "open", process: "rundll32.exe", agent: "WS-SF-022", summary: "DLL side-loading via rundll32", score: "0.91"},
      %{id: "t7", time: "1h ago", level: :suspicious, status: "open", process: "wget", agent: "SRV-LON-002", summary: "Download from suspicious domain", score: "0.55"},
      %{id: "t8", time: "1h ago", level: :malicious, status: "acknowledged", process: "cmd.exe", agent: "WS-NYC-055", summary: "Living off the land binary abuse", score: "0.88"},
      %{id: "t9", time: "2h ago", level: :suspicious, status: "resolved", process: "bash", agent: "SRV-SF-011", summary: "Anomalous cron job creation", score: "0.52"},
      %{id: "t10", time: "3h ago", level: :malicious, status: "open", process: "certutil.exe", agent: "WS-NYC-033", summary: "File download via certutil", score: "0.87"}
    ]
  end
end
