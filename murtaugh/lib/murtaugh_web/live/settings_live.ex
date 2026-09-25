defmodule MurtaughWeb.SettingsLive do
  use MurtaughWeb, :live_view

  alias Murtaugh.{Accounts, Fleet, Repo, Tenancy}
  alias Murtaugh.Alerts.Integration
  alias Murtaugh.Org.Node

  import Ecto.Query, only: [from: 2]

  @roles ~w(viewer analyst admin)
  @retention_choices [30, 90, 180, 365]

  @impl true
  def mount(_params, _session, socket) do
    %{current_user: user, current_org: org} = socket.assigns

    {:ok,
     socket
     |> assign(
       page_title: "Settings",
       active_tab: "users",
       admin?: Accounts.admin?(user, org),
       superadmin?: user.is_superadmin,
       roles: @roles,
       retention_choices: @retention_choices,
       new_token: nil,
       grpc: Application.get_env(:murtaugh, :grpc, [])
     )
     |> load()}
  end

  defp load(%{assigns: %{current_org: org, superadmin?: superadmin?}} = socket) do
    node? = match?(%Node{}, org)

    assign(socket,
      users: if(node?, do: Accounts.list_node_users(org), else: []),
      enrollment_tokens: if(node?, do: Fleet.list_enrollment_tokens(org), else: []),
      integrations: if(node?, do: list_integrations(org), else: []),
      tenants: if(superadmin?, do: Tenancy.list_tenants(), else: [])
    )
  end

  defp list_integrations(%Node{id: id}) do
    Repo.all(from(i in Integration, where: i.org_node_id == ^id, order_by: i.name))
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, active_tab: tab, new_token: nil)}
  end

  def handle_event("add_user", %{"user" => params}, socket) do
    with :ok <- authorize(socket, :admin?),
         role when role in @roles <- params["role"],
         {:ok, user} <- Accounts.add_user_to_node(params, socket.assigns.current_org, role) do
      {:noreply, socket |> put_flash(:info, "Added #{user.email} as #{role}.") |> load()}
    else
      error -> {:noreply, put_flash(socket, :error, "Could not add user: #{describe(error)}")}
    end
  end

  def handle_event("create_token", %{"token" => params}, socket) do
    %{current_org: org, current_user: user} = socket.assigns
    params = Map.reject(params, fn {_k, v} -> v == "" end)

    with :ok <- authorize(socket, :admin?),
         {:ok, _token, plaintext} <- Fleet.create_enrollment_token(org, user, params) do
      {:noreply, socket |> assign(new_token: plaintext) |> load()}
    else
      error -> {:noreply, put_flash(socket, :error, "Could not create token: #{describe(error)}")}
    end
  end

  def handle_event("create_tenant", %{"tenant" => params}, socket) do
    with :ok <- authorize(socket, :superadmin?),
         {days, ""} <- Integer.parse(params["retention_days"] || ""),
         {:ok, %{node: node}} <-
           Tenancy.create_tenant(%{
             name: params["name"],
             slug: params["slug"],
             retention_days: days
           }) do
      {:noreply,
       socket
       |> put_flash(:info, "Tenant #{node.slug} provisioned.")
       |> load()}
    else
      error ->
        {:noreply, put_flash(socket, :error, "Could not create tenant: #{describe(error)}")}
    end
  rescue
    # The shard is left `provisioning` and finished on the next boot.
    e ->
      {:noreply,
       socket
       |> put_flash(
         :error,
         "Tenant saved but its database could not be provisioned (retried on next boot): " <>
           Exception.message(e)
       )
       |> load()}
  end

  def handle_event("save_retention", %{"retention_days" => days}, socket) do
    with :ok <- authorize(socket, :admin?),
         %{} = shard <-
           socket.assigns.current_shard || {:error, "this org has no tenant database"},
         {days, ""} when days in @retention_choices <- Integer.parse(days),
         {:ok, shard} <- Tenancy.update_retention(shard, days) do
      {:noreply,
       socket
       |> assign(current_shard: shard)
       |> put_flash(:info, "Event retention set to #{days} days.")}
    else
      error ->
        {:noreply, put_flash(socket, :error, "Could not save retention: #{describe(error)}")}
    end
  end

  defp authorize(socket, flag) do
    if socket.assigns[flag], do: :ok, else: {:error, "you don't have permission to do that"}
  end

  defp describe({:error, %Ecto.Changeset{} = changeset}) do
    Enum.map_join(changeset.errors, ", ", fn {field, {message, _}} -> "#{field} #{message}" end)
  end

  defp describe({:error, reason}) when is_binary(reason), do: reason
  defp describe(:error), do: "invalid number"
  defp describe(_other), do: "invalid input"

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <h1 class="text-2xl font-bold text-white">Settings</h1>

      <%!-- Tab bar --%>
      <div class="flex gap-1 bg-gray-800 border border-gray-700 rounded-xl p-1">
        <button
          :for={
            {id, label} <-
              [
                {"users", "Users"},
                {"tokens", "Enrollment Tokens"},
                {"alerts", "Alert Integrations"},
                {"retention", "Retention"},
                {"mtls", "Agent TLS"}
              ] ++ if(@superadmin?, do: [{"tenants", "Tenants"}], else: [])
          }
          phx-click="switch_tab"
          phx-value-tab={id}
          class={"px-4 py-2 text-sm rounded-lg transition-colors " <> if @active_tab == id, do: "bg-gray-700 text-white", else: "text-gray-400 hover:text-gray-200"}
        >
          {label}
        </button>
      </div>

      <%!-- Users tab --%>
      <div :if={@active_tab == "users"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Users with access to this org</h2>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-gray-400 border-b border-gray-700">
              <th class="text-left py-2 px-4 font-medium">Name</th>
              <th class="text-left py-2 px-4 font-medium">Email</th>
              <th class="text-left py-2 px-4 font-medium">Role</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={{user, role} <- @users} class="border-b border-gray-700/50">
              <td class="py-2 px-4 text-gray-200">{user.name}</td>
              <td class="py-2 px-4 text-gray-300">{user.email}</td>
              <td class="py-2 px-4 text-gray-300">{role}</td>
            </tr>
            <tr :if={@users == []}>
              <td colspan="3" class="py-4 px-4 text-gray-500">
                No users are granted directly on this org.
              </td>
            </tr>
          </tbody>
        </table>

        <form :if={@admin?} phx-submit="add_user" class="mt-6 grid grid-cols-5 gap-2">
          <input name="user[name]" placeholder="Name" required class={input_class()} />
          <input name="user[email]" type="email" placeholder="Email" required class={input_class()} />
          <input
            name="user[password]"
            type="password"
            placeholder="Initial password (8+)"
            required
            class={input_class()}
          />
          <select name="user[role]" class={input_class()}>
            <option :for={role <- @roles} value={role}>{role}</option>
          </select>
          <button class={button_class()}>Add User</button>
        </form>
      </div>

      <%!-- Enrollment tokens tab --%>
      <div :if={@active_tab == "tokens"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Enrollment Tokens</h2>

        <div :if={@new_token} class="mb-4 rounded-lg border border-green-700 bg-green-900/30 p-4">
          <p class="text-sm text-green-300 mb-2">
            New token — copy it now, it is stored hashed and can't be shown again:
          </p>
          <code id="new-token" class="block font-mono text-sm text-white break-all">
            {@new_token}
          </code>
        </div>

        <table class="w-full text-sm">
          <thead>
            <tr class="text-gray-400 border-b border-gray-700">
              <th class="text-left py-2 px-4 font-medium">Label</th>
              <th class="text-left py-2 px-4 font-medium">Uses Remaining</th>
              <th class="text-left py-2 px-4 font-medium">Expires</th>
              <th class="text-left py-2 px-4 font-medium">Created By</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={token <- @enrollment_tokens} class="border-b border-gray-700/50">
              <td class="py-2 px-4 text-gray-200">{token.label || "—"}</td>
              <td class="py-2 px-4 text-gray-300">{token.uses_remaining || "unlimited"}</td>
              <td class="py-2 px-4 text-gray-400">{token.expires_at || "never"}</td>
              <td class="py-2 px-4 text-gray-300">{token.creator && token.creator.email}</td>
            </tr>
            <tr :if={@enrollment_tokens == []}>
              <td colspan="4" class="py-4 px-4 text-gray-500">No enrollment tokens yet.</td>
            </tr>
          </tbody>
        </table>

        <form :if={@admin?} phx-submit="create_token" class="mt-6 grid grid-cols-4 gap-2">
          <input name="token[label]" placeholder="Label" class={input_class()} />
          <input
            name="token[uses_remaining]"
            type="number"
            min="1"
            placeholder="Uses (blank = unlimited)"
            class={input_class()}
          />
          <input name="token[expires_at]" type="datetime-local" class={input_class()} />
          <button class={button_class()}>Generate Token</button>
        </form>
      </div>

      <%!-- Alerts tab --%>
      <div :if={@active_tab == "alerts"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Alert Integrations</h2>
        <ul class="space-y-2 text-sm">
          <li :for={i <- @integrations} class="flex justify-between text-gray-300">
            <span>{i.name} ({i.integration_type})</span>
            <span class={if i.enabled, do: "text-green-400", else: "text-gray-500"}>
              {if i.enabled, do: "enabled", else: "disabled"}
            </span>
          </li>
        </ul>
        <p :if={@integrations == []} class="text-gray-500 text-sm">
          No integrations configured for this org.
        </p>
      </div>

      <%!-- Retention tab --%>
      <div :if={@active_tab == "retention"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Event Retention</h2>
        <p :if={is_nil(@current_shard)} class="text-gray-500 text-sm">
          This org has no tenant database.
        </p>
        <form
          :if={@current_shard}
          phx-submit="save_retention"
          class="flex items-end gap-3 max-w-lg"
        >
          <div class="flex-1">
            <label class="block text-sm text-gray-300 mb-1">
              Telemetry events older than this are dropped
            </label>
            <select name="retention_days" disabled={!@admin?} class={input_class() <> " w-full"}>
              <option
                :for={days <- @retention_choices}
                value={days}
                selected={days == @current_shard.retention_days}
              >
                {days} days
              </option>
            </select>
          </div>
          <button :if={@admin?} class={button_class()}>Save</button>
        </form>
      </div>

      <%!-- Agent TLS tab --%>
      <div :if={@active_tab == "mtls"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Agent gRPC TLS</h2>
        <div class="bg-gray-900 rounded-lg p-4 space-y-3 text-sm">
          <div class="flex justify-between">
            <span class="text-gray-400">Mode (MURTAUGH_GRPC_TLS_MODE)</span>
            <span class="text-gray-200">{@grpc[:tls_mode] || "optional"}</span>
          </div>
          <div class="flex justify-between">
            <span class="text-gray-400">Mutual TLS</span>
            <span class={if @grpc[:tls], do: "text-green-400", else: "text-amber-400"}>
              {if @grpc[:tls], do: "enabled", else: "not configured — agents connect in cleartext"}
            </span>
          </div>
          <div
            :for={{label, key} <- [{"Server cert", :certfile}, {"CA", :cacertfile}]}
            :if={@grpc[:tls]}
          >
            <div class="flex justify-between">
              <span class="text-gray-400">{label}</span>
              <span class="text-gray-200 font-mono text-xs">{@grpc[:tls][key]}</span>
            </div>
          </div>
        </div>
      </div>

      <%!-- Tenants tab (superadmin) --%>
      <div
        :if={@superadmin? and @active_tab == "tenants"}
        class="bg-gray-800 border border-gray-700 rounded-xl p-5"
      >
        <h2 class="text-lg font-semibold text-white mb-4">Tenants</h2>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-gray-400 border-b border-gray-700">
              <th class="text-left py-2 px-4 font-medium">Name</th>
              <th class="text-left py-2 px-4 font-medium">Slug</th>
              <th class="text-left py-2 px-4 font-medium">Database</th>
              <th class="text-left py-2 px-4 font-medium">Status</th>
              <th class="text-left py-2 px-4 font-medium">Retention</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={{node, shard} <- @tenants} class="border-b border-gray-700/50">
              <td class="py-2 px-4 text-gray-200">{node.name}</td>
              <td class="py-2 px-4 text-gray-300">{node.slug}</td>
              <td class="py-2 px-4 text-gray-400 font-mono text-xs">
                {shard && shard.database_name}
              </td>
              <td class="py-2 px-4 text-gray-300">{(shard && shard.status) || "no shard"}</td>
              <td class="py-2 px-4 text-gray-300">{shard && "#{shard.retention_days} days"}</td>
            </tr>
          </tbody>
        </table>

        <form phx-submit="create_tenant" class="mt-6 grid grid-cols-4 gap-2">
          <input name="tenant[name]" placeholder="Name (Acme Corp)" required class={input_class()} />
          <input
            name="tenant[slug]"
            placeholder="slug (acme)"
            pattern="[a-z0-9][a-z0-9-]*"
            required
            class={input_class()}
          />
          <select name="tenant[retention_days]" class={input_class()}>
            <option :for={days <- @retention_choices} value={days} selected={days == 90}>
              {days} days
            </option>
          </select>
          <button class={button_class()}>Create Tenant</button>
        </form>
      </div>
    </div>
    """
  end

  defp input_class,
    do: "bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-2"

  defp button_class,
    do: "px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg"
end
