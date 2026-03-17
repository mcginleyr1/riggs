defmodule Murtaugh.Grpc.AgentServiceImpl do
  @moduledoc """
  gRPC server implementation for the Riggs agent protocol.

  Handles enrollment, heartbeat streams, telemetry ingestion, threat
  reports, DLP events, and more. Delegates to Murtaugh.Ingest for
  actual data processing and tenant routing.
  """
  use GRPC.Server, service: Riggs.V1.AgentService.Service

  require Logger

  alias Murtaugh.Ingest

  def enroll(request, _stream) do
    case Ingest.enroll_agent(request) do
      {:ok, agent_id} ->
        Logger.info("Agent enrolled: #{agent_id} (#{request.hostname})")

        %Riggs.V1.EnrollResponse{
          agent_id: agent_id,
          heartbeat_interval_secs: 30,
          event_batch_size: 100,
          event_flush_interval_ms: 5000
        }

      {:error, :invalid_token} ->
        raise GRPC.RPCError, status: :unauthenticated, message: "invalid enrollment token"

      {:error, :no_shard} ->
        raise GRPC.RPCError, status: :failed_precondition, message: "no tenant shard configured for org"

      {:error, reason} ->
        Logger.error("Enrollment failed: #{inspect(reason)}")
        raise GRPC.RPCError, status: :internal, message: "enrollment failed"
    end
  end

  def heartbeat(request_enum, _stream) do
    Stream.map(request_enum, fn req ->
      Ingest.record_heartbeat(req.agent_id, req.health)
      %Riggs.V1.HeartbeatResponse{accepted: true}
    end)
  end

  def stream_events(request_enum, _stream) do
    Stream.map(request_enum, fn batch ->
      case Ingest.ingest_events(batch.agent_id, batch.events) do
        {:ok, _count} ->
          %Riggs.V1.EventAck{batch_seq: batch.batch_seq, accepted: true}

        {:error, _reason} ->
          %Riggs.V1.EventAck{batch_seq: batch.batch_seq, accepted: false}
      end
    end)
  end

  def report_threat(request, _stream) do
    case Ingest.ingest_threat(request) do
      {:ok, threat_id} ->
        %Riggs.V1.ThreatAck{accepted: true, threat_id: threat_id}

      {:error, reason} ->
        Logger.error("Threat ingestion failed: #{inspect(reason)}")
        %Riggs.V1.ThreatAck{accepted: false}
    end
  end

  def report_dlp_event(request, _stream) do
    Ingest.ingest_dlp_event(request)
    %Riggs.V1.DlpEventAck{accepted: true}
  end

  def report_vuln_scan(request, _stream) do
    case Ingest.ingest_vuln_scan(request) do
      {:ok, count} ->
        %Riggs.V1.VulnScanAck{accepted: true, findings_stored: count}

      {:error, _reason} ->
        %Riggs.V1.VulnScanAck{accepted: false, findings_stored: 0}
    end
  end

  def report_device_event(request, _stream) do
    Ingest.ingest_device_event(request)
    %Riggs.V1.DeviceEventAck{accepted: true}
  end

  def update_network_map(request, _stream) do
    Ingest.update_network_map(request)
    %Riggs.V1.NetworkMapAck{accepted: true}
  end

  def update_storyline(request, _stream) do
    Ingest.update_storyline(request)
    %Riggs.V1.StorylineAck{accepted: true}
  end
end
