defmodule Murtaugh.Ingest do
  @moduledoc """
  Public API for ingesting telemetry from Riggs agents.

  The gRPC server calls into this module. Sub-modules handle tenant
  routing via AgentRegistry + Tenancy.with_tenant/2.
  """

  defdelegate enroll_agent(request), to: Murtaugh.Ingest.Enrollment
  defdelegate record_heartbeat(agent_id, health), to: Murtaugh.Ingest.Heartbeat
  defdelegate ingest_events(agent_id, events), to: Murtaugh.Ingest.EventIngester
  defdelegate ingest_threat(report), to: Murtaugh.Ingest.ThreatIngester
  defdelegate ingest_dlp_event(report), to: Murtaugh.Ingest.DlpIngester
  defdelegate ingest_vuln_scan(report), to: Murtaugh.Ingest.VulnIngester
  defdelegate ingest_device_event(report), to: Murtaugh.Ingest.DeviceIngester
  defdelegate update_network_map(update), to: Murtaugh.Ingest.NetworkIngester
  defdelegate update_storyline(update), to: Murtaugh.Ingest.StorylineIngester
end
