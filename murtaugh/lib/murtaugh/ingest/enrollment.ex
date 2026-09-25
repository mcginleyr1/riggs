defmodule Murtaugh.Ingest.Enrollment do
  @moduledoc "Validates enrollment token, upserts agent in tenant DB."

  import Ecto.Query

  alias Murtaugh.{Repo, Tenancy, TenantRepo}
  alias Murtaugh.Fleet.{Agent, EnrollmentToken}
  alias Murtaugh.Ingest.AgentRegistry

  def enroll_agent(request) do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    with {:ok, token_record} <- find_valid_token(request.enrollment_token),
         org_node <- Repo.get!(Murtaugh.Org.Node, token_record.org_node_id),
         {:ok, shard} <- Tenancy.resolve_shard(org_node) do
      result =
        Tenancy.with_tenant(shard, fn ->
          attrs = %{
            org_node_id: token_record.org_node_id,
            hostname: request.hostname,
            os: request.os,
            os_version: request.os_version,
            arch: request.arch,
            agent_version: request.agent_version,
            ip_address: request.ip_address,
            mac_address: request.mac_address,
            status: "online",
            enrolled_at: now,
            last_heartbeat: now
          }

          TenantRepo.insert(Agent.changeset(%Agent{}, attrs),
            on_conflict:
              {:replace,
               [:ip_address, :agent_version, :status, :last_heartbeat, :os_version, :arch]},
            conflict_target: [:hostname, :org_node_id],
            returning: true
          )
        end)

      case result do
        {:ok, agent} ->
          AgentRegistry.register(agent.id, shard, token_record.org_node_id)
          maybe_decrement_token(token_record)

          Phoenix.PubSub.broadcast(
            Murtaugh.PubSub,
            Murtaugh.Topics.fleet(agent.org_node_id),
            {:agent_online, agent}
          )

          {:ok, agent.id}

        {:error, changeset} ->
          {:error, changeset}
      end
    end
  end

  defp find_valid_token(token_str) do
    now = DateTime.utc_now()
    hashed = EnrollmentToken.hash_token(token_str)

    query =
      from(t in EnrollmentToken,
        where: t.token == ^hashed,
        where: is_nil(t.expires_at) or t.expires_at > ^now,
        where: is_nil(t.uses_remaining) or t.uses_remaining > 0
      )

    case Repo.one(query) do
      nil -> {:error, :invalid_token}
      token -> {:ok, token}
    end
  end

  defp maybe_decrement_token(%EnrollmentToken{uses_remaining: nil}), do: :ok

  defp maybe_decrement_token(%EnrollmentToken{id: id, uses_remaining: n}) when n > 1 do
    Repo.update_all(from(t in EnrollmentToken, where: t.id == ^id), inc: [uses_remaining: -1])
  end

  defp maybe_decrement_token(%EnrollmentToken{id: id}) do
    Repo.delete_all(from(t in EnrollmentToken, where: t.id == ^id))
  end
end
