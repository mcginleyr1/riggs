defmodule Murtaugh.Fleet do
  @moduledoc """
  Fleet management context for tenant-scoped agent operations.
  """

  import Ecto.Query

  alias Murtaugh.{Repo, TenantRepo}
  alias Murtaugh.Tenancy
  alias Murtaugh.Fleet.{Agent, EnrollmentToken}

  @doc "Enrollment tokens for an org node, newest first."
  def list_enrollment_tokens(%{id: node_id}) do
    from(t in EnrollmentToken,
      where: t.org_node_id == ^node_id,
      order_by: [desc: t.inserted_at],
      preload: :creator
    )
    |> Repo.all()
  end

  @doc """
  Creates an enrollment token for `node`. Returns `{:ok, token, plaintext}`;
  only the hash is stored, so the plaintext must be shown to the operator now.
  """
  def create_enrollment_token(%{id: node_id}, %{id: user_id}, attrs) do
    plaintext = "enrl_" <> Base.url_encode64(:crypto.strong_rand_bytes(24), padding: false)

    attrs =
      Map.merge(attrs, %{
        "org_node_id" => node_id,
        "created_by" => user_id,
        "token" => EnrollmentToken.hash_token(plaintext)
      })

    with {:ok, token} <- %EnrollmentToken{} |> EnrollmentToken.changeset(attrs) |> Repo.insert() do
      {:ok, token, plaintext}
    end
  end

  def list_agents(shard, opts \\ []) do
    Tenancy.with_tenant(shard, fn ->
      limit = Keyword.get(opts, :limit, 100)
      status = Keyword.get(opts, :status)
      org_node_id = Keyword.get(opts, :org_node_id)

      Agent
      |> maybe_filter_status(status)
      |> maybe_filter_org_node(org_node_id)
      |> order_by([a], desc: a.last_heartbeat)
      |> limit(^limit)
      |> TenantRepo.all()
    end)
  end

  def get_agent!(shard, agent_id) do
    Tenancy.with_tenant(shard, fn ->
      TenantRepo.get!(Agent, agent_id)
    end)
  end

  def create_agent(shard, attrs) do
    Tenancy.with_tenant(shard, fn ->
      %Agent{}
      |> Agent.changeset(attrs)
      |> TenantRepo.insert()
    end)
  end

  def update_agent_health(shard, %Agent{} = agent, attrs) do
    Tenancy.with_tenant(shard, fn ->
      agent
      |> Agent.health_changeset(attrs)
      |> TenantRepo.update()
    end)
  end

  def update_agent_health(shard, agent_id, attrs) when is_binary(agent_id) do
    Tenancy.with_tenant(shard, fn ->
      agent = TenantRepo.get!(Agent, agent_id)

      agent
      |> Agent.health_changeset(attrs)
      |> TenantRepo.update()
    end)
  end

  defp maybe_filter_status(query, nil), do: query
  defp maybe_filter_status(query, status), do: where(query, [a], a.status == ^status)

  def count_by_status(shard) do
    Tenancy.with_tenant(shard, fn ->
      from(a in Agent,
        group_by: a.status,
        select: {a.status, count(a.id)}
      )
      |> TenantRepo.all()
      |> Map.new()
    end)
  end

  defp maybe_filter_org_node(query, nil), do: query

  defp maybe_filter_org_node(query, org_node_id),
    do: where(query, [a], a.org_node_id == ^org_node_id)
end
