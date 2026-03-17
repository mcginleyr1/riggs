defmodule Murtaugh.Accounts do
  import Ecto.Query
  alias Murtaugh.Repo
  alias Murtaugh.Accounts.{User, Grant}
  alias Murtaugh.Org.Node

  def register_user(attrs) do
    %User{}
    |> User.registration_changeset(attrs)
    |> Repo.insert()
  end

  def authenticate_user(email, password) do
    user = Repo.get_by(User, email: email)

    cond do
      user && Bcrypt.verify_pass(password, user.password_hash) ->
        {:ok, user}

      user ->
        {:error, :invalid_credentials}

      true ->
        Bcrypt.no_user_verify()
        {:error, :invalid_credentials}
    end
  end

  def get_user!(id) do
    Repo.get!(User, id)
  end

  def list_users do
    Repo.all(User)
  end

  def grant_access(user_id, org_node_id, role) do
    %Grant{}
    |> Grant.changeset(%{user_id: user_id, org_node_id: org_node_id, role: role})
    |> Repo.insert()
  end

  def revoke_access(user_id, org_node_id) do
    case Repo.get_by(Grant, user_id: user_id, org_node_id: org_node_id) do
      nil -> {:error, :not_found}
      grant -> Repo.delete(grant)
    end
  end

  @doc """
  Checks if a user can access the target node.
  A superadmin bypasses the check.
  Otherwise, the user needs a grant on the target node or any of its ancestors
  (nested set: grant_node.lft <= target.lft AND grant_node.rgt >= target.rgt).
  Uses raw SQL for performance.
  """
  def user_can_access?(%User{is_superadmin: true}, _target_node), do: true

  def user_can_access?(%User{id: user_id}, %Node{lft: lft, rgt: rgt}) do
    %{num_rows: count} =
      Repo.query!(
        """
        SELECT 1 FROM user_grants g
        JOIN org_nodes n ON n.id = g.org_node_id
        WHERE g.user_id = $1
          AND n.lft <= $2
          AND n.rgt >= $3
        LIMIT 1
        """,
        [Ecto.UUID.dump!(user_id), lft, rgt]
      )

    count > 0
  end

  @doc """
  Returns all org nodes accessible to a user via their grants.
  Each grant gives access to the granted node and all its descendants.
  Uses raw SQL nested set expansion for performance.
  """
  def accessible_nodes(%User{is_superadmin: true}) do
    Repo.all(from(n in Node, order_by: n.lft))
  end

  def accessible_nodes(%User{id: user_id}) do
    %{rows: rows, columns: columns} =
      Repo.query!(
        """
        SELECT DISTINCT d.*
        FROM user_grants g
        JOIN org_nodes granted ON granted.id = g.org_node_id
        JOIN org_nodes d ON d.lft >= granted.lft AND d.rgt <= granted.rgt
        WHERE g.user_id = $1
        ORDER BY d.lft
        """,
        [Ecto.UUID.dump!(user_id)]
      )

    Enum.map(rows, fn row ->
      columns
      |> Enum.zip(row)
      |> Map.new()
      |> load_node()
    end)
  end

  defp load_node(row) do
    Repo.load(Node, row)
  end
end
