defmodule MurtaughWeb.OrgHook do
  @moduledoc """
  LiveView on_mount hook that extracts the org context from URL params.

  Assigns `org_slug` and `current_org` to the socket. When the Org context
  is built out, this will load the real org node and resolve the tenant shard.
  For now it assigns placeholder data.
  """
  import Phoenix.LiveView
  import Phoenix.Component, only: [assign: 3]

  def on_mount(:default, params, session, socket) do
    org_slug = params["org_slug"] || "default"
    user_id = session["user_id"]

    if user_id do
      # Placeholder user -- will be replaced with Accounts.get_user/1
      current_user = %{id: user_id, email: "operator@riggs.local", name: "Operator", role: :admin}

      # Placeholder org -- will be replaced with Org.get_by_slug/1
      current_org = %{
        id: "00000000-0000-0000-0000-000000000001",
        slug: org_slug,
        name: org_slug |> String.replace("-", " ") |> String.split() |> Enum.map(&String.capitalize/1) |> Enum.join(" "),
        node_type: "account"
      }

      socket =
        socket
        |> assign(:org_slug, org_slug)
        |> assign(:current_org, current_org)
        |> assign(:current_user, current_user)

      {:cont, socket}
    else
      {:halt, redirect(socket, to: "/login")}
    end
  end
end
