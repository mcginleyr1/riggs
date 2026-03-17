defmodule MurtaughWeb.OrgHook do
  @moduledoc """
  LiveView on_mount hook that resolves the org from URL params and
  assigns current_org, current_user, org_slug, and current_shard to
  the socket. Redirects to login if no session user.
  """
  import Phoenix.LiveView
  import Phoenix.Component, only: [assign: 2]

  alias Murtaugh.{Accounts, Org, Tenancy}

  def on_mount(:default, params, session, socket) do
    org_slug = params["org_slug"] || "default"
    user_id = session["user_id"]

    if user_id do
      current_user = load_user(user_id)
      {current_org, current_shard} = resolve_org(org_slug)

      {:cont, assign(socket,
        org_slug: org_slug,
        current_org: current_org,
        current_user: current_user,
        current_shard: current_shard
      )}
    else
      {:halt, redirect(socket, to: "/login")}
    end
  end

  defp load_user(user_id) do
    Accounts.get_user!(user_id)
  rescue
    _ -> %{id: user_id, email: "operator@riggs.local", name: "Operator", role: :admin}
  end

  defp resolve_org(slug) do
    org_node = Org.get_node_by_slug!(slug)

    shard =
      case Tenancy.resolve_shard(org_node) do
        {:ok, shard} -> shard
        {:error, _} -> nil
      end

    {org_node, shard}
  rescue
    _ ->
      fallback = %{
        id: "00000000-0000-0000-0000-000000000001",
        slug: slug,
        name: slug |> String.replace("-", " ") |> String.split() |> Enum.map(&String.capitalize/1) |> Enum.join(" "),
        node_type: "account"
      }

      {fallback, nil}
  end
end
