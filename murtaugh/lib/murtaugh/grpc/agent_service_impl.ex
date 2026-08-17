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
  alias Murtaugh.Grpc.AgentAuth

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

  def heartbeat(request_enum, stream) do
    Stream.map(request_enum, fn req ->
      AgentAuth.verify!(stream, req.agent_id)
      Ingest.record_heartbeat(req.agent_id, req.health)
      %Riggs.V1.HeartbeatResponse{accepted: true}
    end)
  end

  def stream_events(request_enum, stream) do
    Stream.map(request_enum, fn batch ->
      AgentAuth.verify!(stream, batch.agent_id)

      case Ingest.ingest_events(batch.agent_id, batch.events) do
        {:ok, _count} ->
          %Riggs.V1.EventAck{batch_seq: batch.batch_seq, accepted: true}

        {:error, _reason} ->
          %Riggs.V1.EventAck{batch_seq: batch.batch_seq, accepted: false}
      end
    end)
  end

  def report_threat(request, stream) do
    AgentAuth.verify!(stream, request.agent_id)

    case Ingest.ingest_threat(request) do
      {:ok, threat_id} ->
        %Riggs.V1.ThreatAck{accepted: true, threat_id: threat_id}

      {:error, reason} ->
        Logger.error("Threat ingestion failed: #{inspect(reason)}")
        %Riggs.V1.ThreatAck{accepted: false}
    end
  end

  def report_dlp_event(request, stream) do
    AgentAuth.verify!(stream, request.agent_id)
    %Riggs.V1.DlpEventAck{accepted: ingest_ok?(Ingest.ingest_dlp_event(request))}
  end

  def report_vuln_scan(request, stream) do
    AgentAuth.verify!(stream, request.agent_id)

    case Ingest.ingest_vuln_scan(request) do
      {:ok, count} ->
        %Riggs.V1.VulnScanAck{accepted: true, findings_stored: count}

      {:error, _reason} ->
        %Riggs.V1.VulnScanAck{accepted: false, findings_stored: 0}
    end
  end

  def report_device_event(request, stream) do
    AgentAuth.verify!(stream, request.agent_id)
    %Riggs.V1.DeviceEventAck{accepted: ingest_ok?(Ingest.ingest_device_event(request))}
  end

  def update_network_map(request, stream) do
    AgentAuth.verify!(stream, request.agent_id)
    %Riggs.V1.NetworkMapAck{accepted: ingest_ok?(Ingest.update_network_map(request))}
  end

  def update_storyline(request, stream) do
    AgentAuth.verify!(stream, request.agent_id)
    %Riggs.V1.StorylineAck{accepted: ingest_ok?(Ingest.update_storyline(request))}
  end

  # An ingest result of {:error, _} (unknown agent, changeset failure, ...) must
  # be acked as not-accepted so the agent retries instead of dropping its copy.
  defp ingest_ok?({:error, _}), do: false
  defp ingest_ok?(_), do: true
end
