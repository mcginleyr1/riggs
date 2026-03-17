defmodule MurtaughWeb.Presenters do
  @moduledoc """
  Transforms Ecto structs into view-friendly maps matching template keys.
  Keeps presentation logic out of LiveViews and contexts.
  """

  def present_agent(%{id: id} = agent) do
    %{
      id: id,
      hostname: agent.hostname,
      os: agent.os,
      status: String.to_existing_atom(agent.status),
      last_heartbeat: time_ago(agent.last_heartbeat),
      threats: agent.threats_detected || 0,
      dlp_blocks: agent.dlp_blocks || 0,
      version: agent.agent_version || "unknown"
    }
  end

  def present_agent_detail(%{id: id} = agent) do
    %{
      id: id,
      hostname: agent.hostname,
      os: "#{agent.os} #{agent.os_version}",
      status: String.to_existing_atom(agent.status),
      last_heartbeat: time_ago(agent.last_heartbeat),
      version: agent.agent_version || "unknown",
      ip: agent.ip_address || "unknown",
      enrolled_at: format_date(agent.enrolled_at),
      uptime_secs: agent.uptime_secs || 0,
      pipeline_latency_us: agent.pipeline_latency_us || 0,
      sensor_healthy: agent.sensor_healthy
    }
  end

  def present_threat(%{id: id} = threat) do
    %{
      id: id,
      time: time_ago(threat.timestamp),
      level: String.to_existing_atom(threat.threat_level),
      process: threat.process_name || "unknown",
      agent: threat.agent_id |> String.slice(0..7),
      status: threat.status,
      score: Float.to_string(threat.final_score || 0.0),
      summary: threat.summary || "",
      storyline_id: threat.storyline_id
    }
  end

  def present_event(%{} = event) do
    %{
      id: event.id,
      time: format_time(event.timestamp),
      event_type: event.event_type,
      severity: coerce_atom(event.severity),
      process: event.process_name || "unknown",
      description: event_description(event),
      agent: (event.agent_id || "") |> String.slice(0..7),
      payload: event.payload || %{}
    }
  end

  def present_dlp_event(%{id: id} = event) do
    %{
      id: id,
      time: time_ago(event.timestamp),
      action: event.action,
      domain: event.domain,
      process: event.process_name,
      agent: (event.agent_id || "") |> String.slice(0..7),
      agent_id: event.agent_id,
      policy: event.domain_category || "default",
      file_type: event.file_type
    }
  end

  def present_verdict(%{"source" => source} = v) do
    %{
      stage: source,
      verdict: coerce_atom(v["threat_level"]),
      confidence: round((v["confidence"] || 0.0) * 100),
      description: v["description"] || ""
    }
  end

  # Time formatting

  defp time_ago(nil), do: "never"

  defp time_ago(%DateTime{} = dt) do
    diff = DateTime.diff(DateTime.utc_now(), dt, :second)

    cond do
      diff < 60 -> "#{diff}s ago"
      diff < 3600 -> "#{div(diff, 60)}m ago"
      diff < 86400 -> "#{div(diff, 3600)}h ago"
      true -> "#{div(diff, 86400)}d ago"
    end
  end

  defp time_ago(_), do: "unknown"

  defp format_time(nil), do: ""
  defp format_time(%DateTime{} = dt), do: Calendar.strftime(dt, "%H:%M:%S")
  defp format_time(_), do: ""

  defp format_date(nil), do: "unknown"
  defp format_date(%DateTime{} = dt), do: Calendar.strftime(dt, "%Y-%m-%d")
  defp format_date(_), do: "unknown"

  defp coerce_atom(s) when is_atom(s), do: s
  defp coerce_atom(s) when is_binary(s), do: String.to_existing_atom(s)
  defp coerce_atom(_), do: :info

  defp event_description(%{event_type: type, process_name: name, payload: payload}) do
    case type do
      "process_create" -> "#{name} spawned (PID #{payload["pid"] || "?"})"
      "network_connect" -> "Connection to #{payload["dst_ip"] || "?"}:#{payload["dst_port"] || "?"}"
      "file_create" -> "Created #{payload["path"] || "file"}"
      "file_read" -> "Read #{payload["path"] || "file"}"
      "dns_query" -> "DNS: #{payload["domain"] || "?"}"
      "registry_set" -> "Registry: #{payload["key"] || "?"}"
      _ -> "#{type}: #{name}"
    end
  end

  defp event_description(_), do: ""
end
