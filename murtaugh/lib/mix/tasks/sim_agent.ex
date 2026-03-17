defmodule Mix.Tasks.Sim.Agent do
  @moduledoc """
  Simulates a Riggs agent connecting to the local gRPC server.

  Enrolls, then streams heartbeats and periodic fake events/threats/DLP
  events so the dashboard shows live data without needing a real agent.

  Usage:
      mix sim.agent
      mix sim.agent --host localhost --port 4001 --token dev-enroll-token-riggs-sim
  """
  use Mix.Task

  require Logger

  @shortdoc "Run a simulated Riggs agent against the local gRPC server"

  @default_host "localhost"
  @default_port 4001
  @default_token "dev-enroll-token-riggs-sim"
  @heartbeat_interval 10_000
  @event_interval 5_000
  @threat_interval 30_000
  @dlp_interval 15_000

  def run(args) do
    Application.ensure_all_started(:grpc)
    Application.ensure_all_started(:gun)

    {opts, _} =
      OptionParser.parse!(args,
        strict: [host: :string, port: :integer, token: :string]
      )

    host = opts[:host] || System.get_env("GRPC_HOST", @default_host)
    port = opts[:port] || String.to_integer(System.get_env("GRPC_PORT", to_string(@default_port)))
    token = opts[:token] || System.get_env("ENROLL_TOKEN", @default_token)

    Logger.info("Sim agent connecting to #{host}:#{port}")

    {:ok, channel} = GRPC.Stub.connect("#{host}:#{port}")

    agent_id = enroll(channel, token)
    Logger.info("Enrolled as agent #{agent_id}")

    run_loops(channel, agent_id)
  end

  defp enroll(channel, token) do
    request = %Riggs.V1.EnrollRequest{
      hostname: "sim-agent-#{:rand.uniform(9999)}",
      os: "Linux",
      os_version: "6.1",
      arch: "aarch64",
      agent_version: "0.4.2-sim",
      ip_address: "172.20.0.100",
      mac_address: "de:ad:be:ef:ca:fe",
      enrollment_token: token
    }

    case Riggs.V1.AgentService.Stub.enroll(channel, request) do
      {:ok, response} ->
        response.agent_id

      {:error, reason} ->
        Logger.error("Enrollment failed: #{inspect(reason)}")
        Logger.info("Retrying in 5s...")
        Process.sleep(5_000)
        enroll(channel, token)
    end
  end

  defp run_loops(channel, agent_id) do
    # Schedule the first beats
    send(self(), :heartbeat)
    send(self(), :event)
    send(self(), :dlp)

    schedule_threat()
    loop(channel, agent_id, 0)
  end

  defp loop(channel, agent_id, tick) do
    receive do
      :heartbeat ->
        send_heartbeat(channel, agent_id, tick)
        Process.send_after(self(), :heartbeat, @heartbeat_interval)
        loop(channel, agent_id, tick + 1)

      :event ->
        send_events(channel, agent_id)
        Process.send_after(self(), :event, @event_interval)
        loop(channel, agent_id, tick)

      :threat ->
        send_threat(channel, agent_id)
        schedule_threat()
        loop(channel, agent_id, tick)

      :dlp ->
        send_dlp(channel, agent_id)
        Process.send_after(self(), :dlp, @dlp_interval)
        loop(channel, agent_id, tick)
    end
  end

  defp schedule_threat do
    # Random jitter so threats don't fire on a fixed interval
    jitter = :rand.uniform(@threat_interval)
    Process.send_after(self(), :threat, @threat_interval + jitter)
  end

  defp send_heartbeat(channel, agent_id, tick) do
    health = %Riggs.V1.AgentHealth{
      events_processed: tick * 120,
      threats_detected: div(tick, 10),
      dlp_blocks: div(tick, 5),
      sensor_healthy: true,
      pipeline_latency_us: 800 + :rand.uniform(400),
      store_size_bytes: 1_024 * 1_024 * (10 + tick),
      uptime_secs: tick * div(@heartbeat_interval, 1000),
      agent_version: "0.4.2-sim",
      config_version: 1
    }

    stream = [{%Riggs.V1.HeartbeatRequest{agent_id: agent_id, health: health}, []}]

    case Riggs.V1.AgentService.Stub.heartbeat(channel, stream) do
      {:ok, _} -> Logger.debug("Heartbeat #{tick} sent")
      {:error, err} -> Logger.warning("Heartbeat failed: #{inspect(err)}")
    end
  end

  defp send_events(channel, agent_id) do
    events = [
      %Riggs.V1.Event{
        event_id: Ecto.UUID.generate(),
        storyline_id: Ecto.UUID.generate(),
        event_type: Enum.random(~w(process_create network_connect file_read dns_query)),
        severity: Enum.random(~w(info low medium)),
        process_context: %Riggs.V1.ProcessContext{
          pid: :rand.uniform(65535),
          name: Enum.random(~w(chrome firefox curl wget python3 bash)),
          username: "ubuntu"
        },
        payload_json: Jason.encode!(%{simulated: true, ts: System.system_time(:second)})
      }
    ]

    batch = %Riggs.V1.EventBatch{
      agent_id: agent_id,
      events: events,
      batch_seq: :rand.uniform(1_000_000)
    }

    stream = [{batch, []}]

    case Riggs.V1.AgentService.Stub.stream_events(channel, stream) do
      {:ok, _} -> :ok
      {:error, err} -> Logger.warning("Event stream failed: #{inspect(err)}")
    end
  end

  defp send_threat(channel, agent_id) do
    process = Enum.random(["powershell.exe", "cmd.exe", "python3", "bash", "curl"])
    level = Enum.random(["suspicious", "malicious"])
    score = if level == "malicious", do: 0.85 + :rand.uniform() * 0.15, else: 0.4 + :rand.uniform() * 0.45

    report = %Riggs.V1.ThreatReport{
      agent_id: agent_id,
      event_id: Ecto.UUID.generate(),
      storyline_id: Ecto.UUID.generate(),
      threat_level: level,
      final_score: score,
      process_name: process,
      process_path: "/usr/bin/#{process}",
      summary: "Simulated #{level} behavior from #{process}",
      verdicts: [
        %Riggs.V1.VerdictDetail{
          source: "SimEngine",
          threat_level: level,
          confidence: score,
          description: "Simulated verdict for testing"
        }
      ]
    }

    case Riggs.V1.AgentService.Stub.report_threat(channel, report) do
      {:ok, ack} -> Logger.info("Threat reported → id=#{ack.threat_id} level=#{level}")
      {:error, err} -> Logger.warning("Threat report failed: #{inspect(err)}")
    end
  end

  defp send_dlp(channel, agent_id) do
    domains = ["paste.ee", "dropbox.com", "mega.nz", "drive.google.com", "anonfiles.com"]
    actions = ["block", "block", "block", "alert"]  # 3:1 ratio

    report = %Riggs.V1.DlpEventReport{
      agent_id: agent_id,
      action: Enum.random(actions),
      pid: :rand.uniform(65535),
      process_name: Enum.random(["chrome", "firefox", "curl", "python3"]),
      file_path: "/home/ubuntu/document.pdf",
      file_type: Enum.random(["application/pdf", "text/plain", "application/zip"]),
      domain: Enum.random(domains),
      domain_category: "file_sharing",
      username: "ubuntu"
    }

    case Riggs.V1.AgentService.Stub.report_dlp_event(channel, report) do
      {:ok, _} -> Logger.debug("DLP event sent: #{report.action} #{report.domain}")
      {:error, err} -> Logger.warning("DLP report failed: #{inspect(err)}")
    end
  end
end
