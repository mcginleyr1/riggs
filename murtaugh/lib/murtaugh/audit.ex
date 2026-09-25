defmodule Murtaugh.Audit do
  @moduledoc "Append-only audit log of user and system actions."

  import Ecto.Query
  alias Murtaugh.Repo
  alias Murtaugh.Audit.Entry

  @doc """
  Logs an audit entry. The user can be nil for system-initiated actions.

  ## Examples

      Murtaugh.Audit.log(user, "create_node", %{type: "org_node", id: node.id}, %{name: "Acme"})
      Murtaugh.Audit.log(nil, "system.maintenance", nil, %{action: "partition_created"})
  """
  def log(user, action, target, detail \\ %{}) do
    {target_type, target_id, org_node_id} = parse_target(target)

    attrs = %{
      user_id: user_id(user),
      org_node_id: org_node_id,
      action: action,
      target_type: target_type,
      target_id: target_id,
      detail: detail,
      timestamp: DateTime.utc_now()
    }

    %Entry{}
    |> Entry.changeset(attrs)
    |> Repo.insert()
  end

  defp user_id(nil), do: nil
  defp user_id(%{id: id}), do: id

  defp parse_target(nil), do: {nil, nil, nil}
  defp parse_target(%{type: type, id: id, org_node_id: org_node_id}), do: {type, id, org_node_id}
  defp parse_target(%{type: type, id: id}), do: {type, id, nil}

  @doc """
  Lists audit entries with optional filters.

  ## Options

    * `:user_id` - filter by user
    * `:org_node_id` - filter by org node
    * `:action` - filter by action string (exact match)
    * `:since` - entries after this datetime
    * `:until` - entries before this datetime
    * `:limit` - max results (default 100)
    * `:offset` - offset for pagination (default 0)
  """
  def list_entries(opts \\ []) do
    limit = Keyword.get(opts, :limit, 100)
    offset = Keyword.get(opts, :offset, 0)

    Entry
    |> order_by([e], desc: e.timestamp)
    |> maybe_filter(:user_id, opts[:user_id])
    |> maybe_filter(:org_node_id, opts[:org_node_id])
    |> maybe_filter(:action, opts[:action])
    |> maybe_filter_since(opts[:since])
    |> maybe_filter_until(opts[:until])
    |> limit(^limit)
    |> offset(^offset)
    |> Repo.all()
  end

  defp maybe_filter(query, _field, nil), do: query
  defp maybe_filter(query, :user_id, val), do: where(query, [e], e.user_id == ^val)
  defp maybe_filter(query, :org_node_id, val), do: where(query, [e], e.org_node_id == ^val)
  defp maybe_filter(query, :action, val), do: where(query, [e], e.action == ^val)

  defp maybe_filter_since(query, nil), do: query
  defp maybe_filter_since(query, dt), do: where(query, [e], e.timestamp >= ^dt)

  defp maybe_filter_until(query, nil), do: query
  defp maybe_filter_until(query, dt), do: where(query, [e], e.timestamp <= ^dt)
end
