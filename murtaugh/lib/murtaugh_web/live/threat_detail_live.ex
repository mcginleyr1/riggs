defmodule MurtaughWeb.ThreatDetailLive do
  use MurtaughWeb, :live_view

  import MurtaughWeb.UIComponents

  alias Murtaugh.{Detection}
  alias MurtaughWeb.Presenters

  @impl true
  def mount(%{"id" => id}, _session, socket) do
    if connected?(socket) do
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, "threats")
    end

    shard = socket.assigns[:current_shard]
    {threat, verdicts, timeline} = load_threat_data(shard, id)

    {:ok, assign(socket,
      page_title: "Threat",
      threat: threat,
      verdicts: verdicts,
      timeline: timeline
    )}
  end

  @impl true
  def handle_event("acknowledge", _params, socket) do
    maybe_update_threat(socket, "investigating")
  end

  def handle_event("resolve", _params, socket) do
    maybe_update_threat(socket, "resolved")
  end

  def handle_event("mark_false_positive", _params, socket) do
    maybe_update_threat(socket, "false_positive")
  end

  defp maybe_update_threat(socket, status) do
    shard = socket.assigns[:current_shard]
    threat = socket.assigns.threat

    if shard && threat.id do
      case Detection.update_threat_status(shard, threat.id, %{status: status}) do
        {:ok, updated} ->
          {:noreply, assign(socket, :threat, Presenters.present_threat(updated))}
        _ ->
          {:noreply, assign(socket, :threat, %{threat | status: status})}
      end
    else
      {:noreply, assign(socket, :threat, %{threat | status: status})}
    end
  end

  defp load_threat_data(nil, id), do: {placeholder_threat(id), placeholder_verdicts(), placeholder_timeline()}

  defp load_threat_data(shard, id) do
    threat_record = Detection.get_threat!(shard, id)
    threat = Presenters.present_threat(threat_record)

    verdicts =
      (get_in(threat_record.verdicts, ["items"]) || [])
      |> Enum.map(&Presenters.present_verdict/1)

    timeline = Detection.list_events(shard, agent_id: threat_record.agent_id, limit: 20)
               |> Enum.map(&Presenters.present_event/1)

    {threat, verdicts, timeline}
  rescue
    _ -> {placeholder_threat(id), placeholder_verdicts(), placeholder_timeline()}
  end

  @impl true
  def handle_info({:threat_updated, _threat}, socket), do: {:noreply, socket}
  def handle_info({:new_threat, _threat}, socket), do: {:noreply, socket}
  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <%!-- Header --%>
      <div class="flex items-start justify-between">
        <div>
          <div class="flex items-center gap-3 mb-1">
            <.link navigate={~p"/orgs/#{@org_slug}/threats"} class="text-gray-400 hover:text-gray-200">
              <span class="hero-arrow-left size-5" /> Back
            </.link>
          </div>
          <h1 class="text-2xl font-bold text-white">{@threat.process}</h1>
          <p class="text-gray-400 mt-1">{@threat.summary}</p>
        </div>
        <div class="flex items-center gap-3">
          <.threat_badge level={@threat.level} />
          <span class="text-gray-400 text-sm">Score: {@threat.score}</span>
        </div>
      </div>

      <%!-- Info bar --%>
      <div class="bg-gray-800 border border-gray-700 rounded-xl p-4 flex flex-wrap gap-6 text-sm">
        <div>
          <span class="text-gray-400">Status:</span>
          <span class="ml-1 text-gray-200 capitalize">{@threat.status}</span>
        </div>
        <div>
          <span class="text-gray-400">Agent:</span>
          <span class="ml-1 text-gray-200">{@threat.agent}</span>
        </div>
        <div>
          <span class="text-gray-400">Detected:</span>
          <span class="ml-1 text-gray-200">{@threat.time}</span>
        </div>
        <div>
          <span class="text-gray-400">Storyline:</span>
          <span class="ml-1 text-blue-400 font-mono text-xs">{@threat.storyline_id}</span>
        </div>
      </div>

      <%!-- Actions --%>
      <div class="flex gap-3">
        <button phx-click="acknowledge" class="px-4 py-2 bg-yellow-700 hover:bg-yellow-600 text-white text-sm rounded-lg">
          Acknowledge
        </button>
        <button phx-click="resolve" class="px-4 py-2 bg-green-700 hover:bg-green-600 text-white text-sm rounded-lg">
          Resolve
        </button>
        <button phx-click="mark_false_positive" class="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-white text-sm rounded-lg">
          False Positive
        </button>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <%!-- Verdict breakdown --%>
        <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <h2 class="text-lg font-semibold text-white mb-4">Verdict Breakdown</h2>
          <div class="space-y-3">
            <div :for={verdict <- @verdicts} class="flex items-center justify-between p-3 bg-gray-900 rounded-lg">
              <div>
                <p class="text-sm font-medium text-gray-200">{verdict.stage}</p>
                <p class="text-xs text-gray-400 mt-0.5">{verdict.description}</p>
              </div>
              <div class="text-right">
                <.threat_badge level={verdict.verdict} />
                <p class="text-xs text-gray-400 mt-1">{verdict.confidence}% confidence</p>
              </div>
            </div>
          </div>
        </div>

        <%!-- Event timeline --%>
        <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <h2 class="text-lg font-semibold text-white mb-4">Event Timeline</h2>
          <div class="space-y-3">
            <div :for={event <- @timeline} class="flex gap-3 p-3 bg-gray-900 rounded-lg">
              <div class="flex-shrink-0 mt-0.5">
                <.severity_badge severity={event.severity} />
              </div>
              <div>
                <p class="text-sm font-medium text-gray-200">{event.event_type}</p>
                <p class="text-xs text-gray-400">{event.description}</p>
                <p class="text-xs text-gray-500 mt-1">{event.time}</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp placeholder_threat(id) do
    %{
      id: id,
      level: :malicious,
      status: "open",
      process: "powershell.exe",
      agent: "WS-NYC-042",
      time: "2026-03-17 09:58:00 UTC",
      score: "0.95",
      summary: "Encoded command execution with network callback to known C2 infrastructure",
      storyline_id: "sl_a1b2c3d4e5f6"
    }
  end

  defp placeholder_verdicts do
    [
      %{stage: "Static Analysis", verdict: :suspicious, confidence: 68, description: "Encoded PowerShell command detected"},
      %{stage: "Behavioral Engine", verdict: :malicious, confidence: 92, description: "Network callback after encoded execution"},
      %{stage: "IOC Match", verdict: :malicious, confidence: 99, description: "C2 IP 185.220.101.42 matches threat intel"},
      %{stage: "YARA Rules", verdict: :suspicious, confidence: 75, description: "Matched rule: CobaltStrike_Beacon_Encoded"}
    ]
  end

  defp placeholder_timeline do
    [
      %{event_type: "process_create", severity: :medium, description: "powershell.exe spawned by explorer.exe", time: "09:57:58 UTC"},
      %{event_type: "file_read", severity: :low, description: "Read C:\\Users\\admin\\payload.ps1", time: "09:57:59 UTC"},
      %{event_type: "network_connect", severity: :high, description: "Outbound TCP to 185.220.101.42:443", time: "09:58:01 UTC"},
      %{event_type: "dns_query", severity: :medium, description: "Resolved update-service.xyz -> 185.220.101.42", time: "09:58:00 UTC"},
      %{event_type: "file_create", severity: :high, description: "Created C:\\Windows\\Temp\\beacon.dll", time: "09:58:03 UTC"},
      %{event_type: "registry_set", severity: :critical, description: "Set persistence key in HKLM\\...\\Run", time: "09:58:05 UTC"}
    ]
  end
end
