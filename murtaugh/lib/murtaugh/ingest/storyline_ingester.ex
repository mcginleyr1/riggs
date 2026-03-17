defmodule Murtaugh.Ingest.StorylineIngester do
  @moduledoc "Upserts storyline state from agents."

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Ingest.AgentRegistry

  def update_storyline(update) do
    case AgentRegistry.lookup(update.agent_id) do
      {:ok, shard, org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          process_tree =
            case update[:process_tree_json] do
              bin when is_binary(bin) and byte_size(bin) > 0 ->
                case Jason.decode(bin) do
                  {:ok, tree} -> tree
                  _ -> %{}
                end
              _ -> %{}
            end

          row = %{
            id: update.storyline_id,
            agent_id: update.agent_id,
            org_node_id: org_node_id,
            root_pid: update.root_pid,
            root_process: update.root_process,
            root_path: update.root_path,
            status: update.status || "active",
            max_severity: update.max_severity || "info",
            threat_count: update.threat_count || 0,
            event_count: update.event_count || 0,
            first_seen: now,
            last_seen: now,
            process_tree: process_tree
          }

          TenantRepo.insert_all("storylines", [row],
            on_conflict: {:replace, [:status, :max_severity, :threat_count, :event_count, :last_seen, :process_tree]},
            conflict_target: [:id]
          )

          :ok
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end
end
