defmodule Murtaugh.Ingest.ThreatIngester do
  @moduledoc "Inserts threat reports into the tenant threats table."

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Detection.Threat
  alias Murtaugh.Ingest.AgentRegistry

  def ingest_threat(report) do
    case AgentRegistry.lookup(report.agent_id) do
      {:ok, shard, org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          verdicts =
            Enum.map(report.verdicts || [], fn v ->
              %{
                "source" => v.source,
                "threat_level" => v.threat_level,
                "confidence" => v.confidence,
                "description" => v.description
              }
            end)

          attrs = %{
            agent_id: report.agent_id,
            org_node_id: org_node_id,
            event_id: coerce_uuid(report.event_id),
            storyline_id: coerce_uuid(report.storyline_id),
            threat_level: report.threat_level,
            final_score: report.final_score,
            status: "open",
            timestamp: now,
            received_at: now,
            verdicts: %{"items" => verdicts},
            process_name: report.process_name,
            process_path: report.process_path,
            summary: report.summary
          }

          case TenantRepo.insert(Threat.changeset(%Threat{}, attrs)) do
            {:ok, threat} ->
              Phoenix.PubSub.broadcast(
                Murtaugh.PubSub,
                Murtaugh.Topics.threats(org_node_id),
                {:new_threat, threat}
              )

              {:ok, threat.id}

            {:error, changeset} ->
              {:error, changeset}
          end
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end

  defp coerce_uuid(nil), do: Ecto.UUID.generate()
  defp coerce_uuid(""), do: Ecto.UUID.generate()

  defp coerce_uuid(s) do
    case Ecto.UUID.cast(s) do
      {:ok, uuid} -> uuid
      :error -> Ecto.UUID.generate()
    end
  end
end
