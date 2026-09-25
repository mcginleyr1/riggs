defmodule Murtaugh.Org do
  @moduledoc "The org hierarchy, stored as a nested set of nodes."

  import Ecto.Query
  alias Murtaugh.Repo
  alias Murtaugh.Org.Node

  def list_nodes do
    Node
    |> order_by([n], n.lft)
    |> Repo.all()
  end

  def get_node!(id) do
    Repo.get!(Node, id)
  end

  def get_node_by_slug!(slug) do
    Repo.get_by!(Node, slug: slug)
  end

  def create_node(attrs) do
    %Node{}
    |> Node.changeset(attrs)
    |> Repo.insert()
  end

  @doc """
  Inserts a node as the last child of `parent`, shifting the nested set to make
  room. Must run inside a transaction; the table lock serializes concurrent inserts.
  """
  def insert_child(%Node{id: parent_id}, attrs) do
    Repo.query!("LOCK TABLE org_nodes IN SHARE ROW EXCLUSIVE MODE")
    parent = Repo.get!(Node, parent_id)

    # lft/rgt have non-deferrable unique indexes, so shift through negative
    # values: no intermediate row can collide with an unshifted one.
    Repo.query!("UPDATE org_nodes SET rgt = -(rgt + 2) WHERE rgt >= $1", [parent.rgt])
    Repo.query!("UPDATE org_nodes SET lft = -(lft + 2) WHERE lft > $1", [parent.rgt])
    Repo.query!("UPDATE org_nodes SET rgt = -rgt WHERE rgt < 0")
    Repo.query!("UPDATE org_nodes SET lft = -lft WHERE lft < 0")

    attrs
    |> Map.merge(%{
      parent_id: parent.id,
      lft: parent.rgt,
      rgt: parent.rgt + 1,
      depth: parent.depth + 1
    })
    |> create_node()
  end

  def update_node(%Node{} = node, attrs) do
    node
    |> Node.changeset(attrs)
    |> Repo.update()
  end

  def delete_node(%Node{} = node) do
    Repo.delete(node)
  end

  @doc """
  Returns all descendants of the given node using nested set lft/rgt range.
  This is a single range scan -- no recursive CTEs needed.
  """
  def descendants(%Node{lft: lft, rgt: rgt}) do
    Repo.all(
      from(n in Node,
        where: n.lft > ^lft and n.rgt < ^rgt,
        order_by: [asc: n.lft]
      )
    )
  end

  @doc """
  Returns all ancestors of the given node using nested set range.
  Ordered from root down to the immediate parent.
  """
  def ancestors(%Node{lft: lft, rgt: rgt}) do
    Repo.all(
      from(n in Node,
        where: n.lft < ^lft and n.rgt > ^rgt,
        order_by: [asc: n.lft]
      )
    )
  end

  @doc """
  Returns a list of descendant IDs for the given node, including the node itself.
  Uses raw SQL for performance on the nested set range query.
  """
  def descendant_ids(%Node{id: id, lft: lft, rgt: rgt}) do
    %{rows: rows} =
      Repo.query!(
        "SELECT id FROM org_nodes WHERE lft >= $1 AND rgt <= $2",
        [lft, rgt]
      )

    rows
    |> Enum.map(fn [raw_id] -> raw_to_uuid(raw_id) end)
    |> then(fn ids ->
      uuid = if is_binary(id) and byte_size(id) == 36, do: id, else: Ecto.UUID.cast!(id)
      if uuid in ids, do: ids, else: [uuid | ids]
    end)
  end

  defp raw_to_uuid(<<_::128>> = raw), do: Ecto.UUID.cast!(raw)
  defp raw_to_uuid(str) when is_binary(str), do: str

  @doc """
  Rebuilds the nested set lft/rgt/depth values for the entire tree.
  Walks the tree from root using parent_id relationships.
  Runs inside a transaction with a serializable isolation level advisory lock.
  """
  def rebuild_tree do
    Repo.transaction(fn ->
      Repo.query!("SELECT pg_advisory_xact_lock(42)")

      nodes = Repo.all(from(n in Node, select: {n.id, n.parent_id}))

      children_map =
        nodes
        |> Enum.group_by(fn {_id, parent_id} -> parent_id end, fn {id, _} -> id end)

      roots = Map.get(children_map, nil, [])

      {updates, _counter} = walk_tree(roots, children_map, 1, 0)

      for {id, lft, rgt, depth} <- updates do
        Repo.query!(
          "UPDATE org_nodes SET lft = $1, rgt = $2, depth = $3 WHERE id = $4",
          [lft, rgt, depth, Ecto.UUID.dump!(id)]
        )
      end

      :ok
    end)
  end

  defp walk_tree([], _children_map, counter, _depth) do
    {[], counter}
  end

  defp walk_tree(node_ids, children_map, counter, depth) do
    Enum.reduce(node_ids, {[], counter}, fn node_id, {acc, c} ->
      lft = c
      children = Map.get(children_map, node_id, [])
      {child_updates, next_c} = walk_tree(children, children_map, c + 1, depth + 1)
      rgt = next_c
      {acc ++ [{node_id, lft, rgt, depth} | child_updates], rgt + 1}
    end)
  end
end
