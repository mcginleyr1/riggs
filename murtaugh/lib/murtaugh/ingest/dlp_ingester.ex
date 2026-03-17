defmodule Murtaugh.Ingest.DlpIngester do
  @moduledoc "Inserts DLP events into the tenant dlp_events table."

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Dlp.Event
  alias Murtaugh.Ingest.AgentRegistry

  def ingest_dlp_event(report) do
    case AgentRegistry.lookup(report.agent_id) do
      {:ok, shard, org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          attrs = %{
            agent_id: report.agent_id,
            org_node_id: org_node_id,
            timestamp: now,
            received_at: now,
            action: report.action,
            pid: report.pid,
            process_name: report.process_name,
            file_path: report.file_path,
            file_type: report.file_type,
            domain: report.domain,
            domain_category: report.domain_category,
            username: report.username
          }

          case TenantRepo.insert(Event.changeset(%Event{}, attrs)) do
            {:ok, event} ->
              Phoenix.PubSub.broadcast(Murtaugh.PubSub, "dlp", {:dlp_event, event})
              {:ok, event.id}

            {:error, changeset} ->
              {:error, changeset}
          end
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end
end
