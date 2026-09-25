defmodule MurtaughWeb.DashboardLive do
  use MurtaughWeb, :live_view

  alias Murtaugh.{Detection, Dlp, Fleet}
  alias MurtaughWeb.Presenters

  @impl true
  def mount(_params, _session, socket) do
    if connected?(socket) do
      org_id = socket.assigns.current_org.id
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, Murtaugh.Topics.threats(org_id))
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, Murtaugh.Topics.dlp(org_id))
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, Murtaugh.Topics.fleet(org_id))
      Phoenix.PubSub.subscribe(Murtaugh.PubSub, Murtaugh.Topics.throughput(org_id))
    end

    shard = socket.assigns[:current_shard]

    {agents_online, agents_offline, agents_degraded, threats_today, recent_threats,
     recent_dlp_blocks, dlp_blocks_today, events_per_sec} =
      load_dashboard_data(shard)

    {:ok,
     assign(socket,
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

    {:noreply,
     assign(socket, threats_today: socket.assigns.threats_today + 1, recent_threats: threats)}
  end

  def handle_info({:threat_updated, _threat}, socket), do: {:noreply, socket}

  def handle_info({:dlp_event, event}, socket) do
    blocks = [
      Presenters.present_dlp_event(event) | Enum.take(socket.assigns.recent_dlp_blocks, 4)
    ]

    {:noreply,
     assign(socket,
       dlp_blocks_today: socket.assigns.dlp_blocks_today + 1,
       recent_dlp_blocks: blocks
     )}
  end

  def handle_info({:agent_online, _agent}, socket),
    do: {:noreply, update(socket, :agents_online, &(&1 + 1))}

  def handle_info({:agent_offline, _agent}, socket),
    do: {:noreply, update(socket, :agents_offline, &(&1 + 1))}

  def handle_info({:agent_status_change, _agent}, socket), do: {:noreply, socket}

  def handle_info({:throughput_update, eps}, socket),
    do: {:noreply, assign(socket, events_per_sec: eps)}

  def handle_info(_msg, socket), do: {:noreply, socket}

  @impl true
  def render(assigns) do
    total_agents = assigns.agents_online + assigns.agents_offline + assigns.agents_degraded

    online_pct =
      if total_agents > 0, do: round(assigns.agents_online / total_agents * 100), else: 0

    assigns = assign(assigns, total_agents: total_agents, online_pct: online_pct)

    ~H"""
    <div class="flex flex-col gap-5 h-full">
      <%!-- ── Metric strip ─────────────────────────────────────────────── --%>
      <div class="grid grid-cols-5 gap-3">
        <.metric
          label="ONLINE AGENTS"
          value={to_string(@agents_online)}
          sub={"+#{@agents_online - 139}"}
          sub_color="#4ade80"
          accent="#22c55e"
        />
        <.metric
          label="OFFLINE"
          value={to_string(@agents_offline)}
          sub="agents down"
          sub_color="rgba(255,255,255,0.3)"
          accent="#ef4444"
        />
        <.metric
          label="THREATS TODAY"
          value={to_string(@threats_today)}
          sub={if @threats_today > 5, do: "↑ above baseline", else: "within baseline"}
          sub_color={if @threats_today > 5, do: "#f87171", else: "rgba(255,255,255,0.3)"}
          accent="#ef4444"
        />
        <.metric
          label="DLP BLOCKS"
          value={to_string(@dlp_blocks_today)}
          sub="exfil prevented"
          sub_color="rgba(255,255,255,0.3)"
          accent="#f59e0b"
        />
        <.metric
          label="EVENTS/SEC"
          value={to_string(@events_per_sec)}
          sub="telemetry stream"
          sub_color="rgba(255,255,255,0.3)"
          accent="#38bdf8"
        />
      </div>

      <%!-- ── Main grid ──────────────────────────────────────────────────── --%>
      <div class="flex gap-4 flex-1 min-h-0">
        <%!-- Left col: threats + DLP --%>
        <div class="flex flex-col gap-4 flex-1 min-w-0">
          <%!-- Threat table --%>
          <div
            class="flex-1 flex flex-col rounded-lg overflow-hidden"
            style="background: #0c0f1a; border: 1px solid rgba(255,255,255,0.06);"
          >
            <div
              class="flex items-center justify-between px-4 py-3"
              style="border-bottom: 1px solid rgba(255,255,255,0.05);"
            >
              <div class="flex items-center gap-2">
                <span class="w-1.5 h-1.5 rounded-full" style="background: #ef4444;"></span>
                <span style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: rgba(255,255,255,0.5);">
                  Recent Threats
                </span>
              </div>
              <.link
                navigate={~p"/orgs/#{@org_slug}/threats"}
                style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; color: rgba(255,255,255,0.25); letter-spacing: 0.05em;"
                class="hover:text-white/50 transition-colors"
              >
                view all →
              </.link>
            </div>

            <div class="flex-1 overflow-auto">
              <table class="w-full text-sm">
                <thead>
                  <tr style="border-bottom: 1px solid rgba(255,255,255,0.04);">
                    <th
                      class="text-left px-4 py-2.5"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.1em; color: rgba(255,255,255,0.25);"
                    >
                      Time
                    </th>
                    <th
                      class="text-left px-4 py-2.5"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.1em; color: rgba(255,255,255,0.25);"
                    >
                      Level
                    </th>
                    <th
                      class="text-left px-4 py-2.5"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.1em; color: rgba(255,255,255,0.25);"
                    >
                      Process
                    </th>
                    <th
                      class="text-left px-4 py-2.5"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.1em; color: rgba(255,255,255,0.25);"
                    >
                      Agent
                    </th>
                  </tr>
                </thead>
                <tbody>
                  <tr
                    :for={threat <- @recent_threats}
                    class="cursor-pointer transition-colors"
                    style="border-bottom: 1px solid rgba(255,255,255,0.03);"
                    phx-click={JS.navigate(~p"/orgs/#{@org_slug}/threats/#{threat.id}")}
                  >
                    <td
                      class="px-4 py-2.5"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.3);"
                    >
                      {threat.time}
                    </td>
                    <td class="px-4 py-2.5">
                      <.threat_chip level={threat.level} />
                    </td>
                    <td
                      class="px-4 py-2.5"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: rgba(255,255,255,0.75);"
                    >
                      {threat.process}
                    </td>
                    <td
                      class="px-4 py-2.5"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.4);"
                    >
                      {threat.agent}
                    </td>
                  </tr>
                  <tr :if={@recent_threats == []}>
                    <td
                      colspan="4"
                      class="px-4 py-8 text-center"
                      style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.2);"
                    >
                      no threats detected
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

          <%!-- DLP blocks --%>
          <div
            class="rounded-lg overflow-hidden"
            style="background: #0c0f1a; border: 1px solid rgba(255,255,255,0.06);"
          >
            <div
              class="flex items-center justify-between px-4 py-3"
              style="border-bottom: 1px solid rgba(255,255,255,0.05);"
            >
              <div class="flex items-center gap-2">
                <span class="w-1.5 h-1.5 rounded-full" style="background: #f59e0b;"></span>
                <span style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: rgba(255,255,255,0.5);">
                  DLP Events
                </span>
              </div>
              <.link
                navigate={~p"/orgs/#{@org_slug}/dlp"}
                style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; color: rgba(255,255,255,0.25); letter-spacing: 0.05em;"
                class="hover:text-white/50 transition-colors"
              >
                view all →
              </.link>
            </div>
            <table class="w-full text-sm">
              <tbody>
                <tr
                  :for={block <- @recent_dlp_blocks}
                  style="border-bottom: 1px solid rgba(255,255,255,0.03);"
                >
                  <td
                    class="px-4 py-2.5 w-20"
                    style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.3);"
                  >
                    {block.time}
                  </td>
                  <td class="px-4 py-2.5 w-16">
                    <span style={"font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 600; letter-spacing: 0.08em; padding: 2px 8px; border-radius: 3px; #{if block.action == "block", do: "background: rgba(239,68,68,0.15); color: #f87171; border: 1px solid rgba(239,68,68,0.3);", else: "background: rgba(245,158,11,0.15); color: #fbbf24; border: 1px solid rgba(245,158,11,0.3);"}"}>
                      {String.upcase(block.action)}
                    </span>
                  </td>
                  <td
                    class="px-4 py-2.5"
                    style="font-family: 'IBM Plex Mono', monospace; font-size: 12px; color: rgba(255,255,255,0.7);"
                  >
                    {block.domain}
                  </td>
                  <td
                    class="px-4 py-2.5"
                    style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.35);"
                  >
                    {block.agent}
                  </td>
                </tr>
                <tr :if={@recent_dlp_blocks == []}>
                  <td
                    colspan="4"
                    class="px-4 py-6 text-center"
                    style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.2);"
                  >
                    no dlp events
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <%!-- Right col: fleet health + activity --%>
        <div class="w-64 flex-shrink-0 flex flex-col gap-4">
          <%!-- Fleet health --%>
          <div
            class="rounded-lg p-4"
            style="background: #0c0f1a; border: 1px solid rgba(255,255,255,0.06);"
          >
            <div class="flex items-center gap-2 mb-4">
              <span class="w-1.5 h-1.5 rounded-full" style="background: #22c55e;"></span>
              <span style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: rgba(255,255,255,0.5);">
                Fleet Health
              </span>
            </div>

            <%!-- Big online count --%>
            <div class="mb-4">
              <div class="flex items-baseline gap-2 mb-1">
                <span style="font-family: 'IBM Plex Mono', monospace; font-size: 2rem; font-weight: 600; color: #22c55e; line-height: 1;">
                  {@online_pct}%
                </span>
                <span style="font-size: 11px; color: rgba(255,255,255,0.3);">online</span>
              </div>
              <%!-- Progress bar --%>
              <div
                class="w-full rounded-full overflow-hidden"
                style="height: 3px; background: rgba(255,255,255,0.08);"
              >
                <div
                  class="h-full rounded-full transition-all duration-500"
                  style={"width: #{@online_pct}%; background: linear-gradient(90deg, #16a34a, #4ade80);"}
                >
                </div>
              </div>
            </div>

            <div class="space-y-2.5">
              <.fleet_row label="Online" count={@agents_online} color="#22c55e" total={@total_agents} />
              <.fleet_row
                label="Degraded"
                count={@agents_degraded}
                color="#f59e0b"
                total={@total_agents}
              />
              <.fleet_row
                label="Offline"
                count={@agents_offline}
                color="#ef4444"
                total={@total_agents}
              />
            </div>

            <.link
              navigate={~p"/orgs/#{@org_slug}/agents"}
              class="block mt-4 text-center py-1.5 rounded transition-colors"
              style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: 0.05em; color: rgba(255,255,255,0.25); border: 1px solid rgba(255,255,255,0.07);"
            >
              all agents →
            </.link>
          </div>

          <%!-- Severity breakdown --%>
          <div
            class="rounded-lg p-4"
            style="background: #0c0f1a; border: 1px solid rgba(255,255,255,0.06);"
          >
            <div class="flex items-center gap-2 mb-4">
              <span class="w-1.5 h-1.5 rounded-full" style="background: #ef4444;"></span>
              <span style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: rgba(255,255,255,0.5);">
                Threat Breakdown
              </span>
            </div>
            <div class="space-y-3">
              <.severity_row
                label="MALICIOUS"
                value={Enum.count(@recent_threats, &(&1.level == :malicious))}
                color="#ef4444"
              />
              <.severity_row
                label="SUSPICIOUS"
                value={Enum.count(@recent_threats, &(&1.level == :suspicious))}
                color="#f59e0b"
              />
              <.severity_row label="DLP BLOCKS" value={@dlp_blocks_today} color="#f59e0b" />
              <.severity_row label="DLP ALERTS" value={@dlp_alerts_today} color="#38bdf8" />
            </div>
          </div>

          <%!-- Stream indicator --%>
          <div
            class="rounded-lg p-4 flex-1"
            style="background: #0c0f1a; border: 1px solid rgba(255,255,255,0.06);"
          >
            <div class="flex items-center gap-2 mb-3">
              <span class="relative flex h-1.5 w-1.5">
                <span
                  class="animate-ping absolute inline-flex h-full w-full rounded-full opacity-75"
                  style="background: #38bdf8;"
                >
                </span>
                <span
                  class="relative inline-flex rounded-full h-1.5 w-1.5"
                  style="background: #38bdf8;"
                >
                </span>
              </span>
              <span style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; letter-spacing: 0.12em; text-transform: uppercase; color: rgba(255,255,255,0.5);">
                Telemetry
              </span>
            </div>
            <div class="flex items-end gap-0.5" style="height: 36px;">
              {Phoenix.HTML.raw(sparkline_bars())}
            </div>
            <p
              class="mt-2"
              style="font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: rgba(255,255,255,0.25);"
            >
              {@events_per_sec} <span style="color: rgba(255,255,255,0.15);">eps</span>
            </p>
          </div>
        </div>
      </div>
    </div>
    """
  end

  ## Private components

  attr :label, :string, required: true
  attr :value, :string, required: true
  attr :sub, :string, required: true
  attr :sub_color, :string, required: true
  attr :accent, :string, required: true

  defp metric(assigns) do
    ~H"""
    <div
      class="rounded-lg px-4 py-3.5"
      style="background: #0c0f1a; border: 1px solid rgba(255,255,255,0.06);"
    >
      <p style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.12em; color: rgba(255,255,255,0.35); margin-bottom: 8px;">
        {@label}
      </p>
      <p style={"font-family: 'IBM Plex Mono', monospace; font-size: 1.75rem; font-weight: 600; line-height: 1; color: #{@accent}; margin-bottom: 6px;"}>
        {@value}
      </p>
      <p style={"font-size: 11px; color: #{@sub_color}; font-family: 'IBM Plex Mono', monospace;"}>
        {@sub}
      </p>
    </div>
    """
  end

  attr :level, :atom, required: true

  defp threat_chip(assigns) do
    {color, border, label} =
      case assigns.level do
        :malicious ->
          {"rgba(239,68,68,0.15)", "rgba(239,68,68,0.4)", "MALICIOUS"}

        :suspicious ->
          {"rgba(245,158,11,0.15)", "rgba(245,158,11,0.4)", "SUSPICIOUS"}

        _ ->
          {"rgba(255,255,255,0.08)", "rgba(255,255,255,0.15)",
           String.upcase(to_string(assigns.level))}
      end

    text_color =
      case assigns.level do
        :malicious -> "#f87171"
        :suspicious -> "#fbbf24"
        _ -> "rgba(255,255,255,0.5)"
      end

    assigns = assign(assigns, color: color, border: border, label: label, text_color: text_color)

    ~H"""
    <span style={"font-family: 'IBM Plex Mono', monospace; font-size: 10px; font-weight: 600; letter-spacing: 0.08em; padding: 2px 7px; border-radius: 3px; background: #{@color}; color: #{@text_color}; border: 1px solid #{@border};"}>
      {@label}
    </span>
    """
  end

  attr :label, :string, required: true
  attr :count, :integer, required: true
  attr :color, :string, required: true
  attr :total, :integer, required: true

  defp fleet_row(assigns) do
    pct = if assigns.total > 0, do: round(assigns.count / assigns.total * 100), else: 0
    assigns = assign(assigns, pct: pct)

    ~H"""
    <div>
      <div class="flex items-center justify-between mb-1">
        <span style={"font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: #{@color}; opacity: 0.8;"}>
          {@label}
        </span>
        <span style={"font-family: 'IBM Plex Mono', monospace; font-size: 11px; color: #{@color};"}>
          {@count}
        </span>
      </div>
      <div
        class="w-full rounded-full overflow-hidden"
        style="height: 2px; background: rgba(255,255,255,0.06);"
      >
        <div
          class="h-full rounded-full"
          style={"width: #{@pct}%; background: #{@color}; opacity: 0.7;"}
        >
        </div>
      </div>
    </div>
    """
  end

  attr :label, :string, required: true
  attr :value, :integer, required: true
  attr :color, :string, required: true

  defp severity_row(assigns) do
    ~H"""
    <div class="flex items-center justify-between">
      <span style="font-family: 'IBM Plex Mono', monospace; font-size: 10px; letter-spacing: 0.08em; color: rgba(255,255,255,0.3);">
        {@label}
      </span>
      <span style={"font-family: 'IBM Plex Mono', monospace; font-size: 13px; font-weight: 600; color: #{@color};"}>
        {@value}
      </span>
    </div>
    """
  end

  defp sparkline_bars do
    # Generate fake sparkline bars using random-looking but stable heights
    heights = [30, 45, 28, 60, 42, 38, 55, 70, 48, 35, 62, 50, 44, 38, 55, 68, 40, 52, 45, 60]
    max_h = Enum.max(heights)

    Enum.map_join(heights, "", fn h ->
      pct = round(h / max_h * 100)
      opacity = 0.3 + pct / 100 * 0.7

      "<div style=\"flex: 1; background: #38bdf8; opacity: #{Float.round(opacity, 2)}; border-radius: 1px; height: #{pct}%; align-self: flex-end;\"></div>"
    end)
  end

  defp load_dashboard_data(nil) do
    {142, 8, 3, 7, placeholder_threats(), placeholder_dlp_blocks(), 23, 1240}
  end

  defp load_dashboard_data(shard) do
    status_counts = Fleet.count_by_status(shard)
    threats_today = Detection.count_threats_today(shard)

    recent_threats =
      shard |> Detection.list_threats(limit: 10) |> Enum.map(&Presenters.present_threat/1)

    recent_dlp = shard |> Dlp.recent_blocks(limit: 5) |> Enum.map(&Presenters.present_dlp_event/1)
    dlp_blocks = Dlp.count_blocks_today(shard)

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
      %{
        id: "t1",
        time: "2m ago",
        level: :malicious,
        process: "powershell.exe",
        agent: "WS-NYC-042"
      },
      %{id: "t2", time: "8m ago", level: :suspicious, process: "curl", agent: "SRV-SF-003"},
      %{
        id: "t3",
        time: "15m ago",
        level: :malicious,
        process: "mimikatz.exe",
        agent: "WS-NYC-017"
      },
      %{id: "t4", time: "22m ago", level: :suspicious, process: "python3", agent: "WS-LON-008"},
      %{id: "t5", time: "31m ago", level: :malicious, process: "rundll32.exe", agent: "WS-SF-022"}
    ]
  end

  defp placeholder_dlp_blocks do
    [
      %{id: "d1", time: "5m ago", action: "block", domain: "paste.ee", agent: "WS-NYC-042"},
      %{id: "d2", time: "12m ago", action: "block", domain: "dropbox.com", agent: "WS-SF-019"},
      %{
        id: "d3",
        time: "28m ago",
        action: "alert",
        domain: "drive.google.com",
        agent: "WS-LON-003"
      },
      %{id: "d4", time: "44m ago", action: "block", domain: "mega.nz", agent: "SRV-NYC-001"}
    ]
  end
end
