defmodule MurtaughWeb.SettingsLive do
  use MurtaughWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "Settings")
      |> assign(:active_tab, "users")
      |> assign(:users, placeholder_users())
      |> assign(:enrollment_tokens, placeholder_tokens())

    {:ok, socket}
  end

  @impl true
  def handle_event("switch_tab", %{"tab" => tab}, socket) do
    {:noreply, assign(socket, :active_tab, tab)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <h1 class="text-2xl font-bold text-white">Settings</h1>

      <%!-- Tab bar --%>
      <div class="flex gap-1 bg-gray-800 border border-gray-700 rounded-xl p-1">
        <button
          :for={tab <- [{"users", "Users"}, {"tokens", "Enrollment Tokens"}, {"alerts", "Alert Integrations"}, {"retention", "Retention"}, {"mtls", "mTLS CA"}]}
          phx-click="switch_tab"
          phx-value-tab={elem(tab, 0)}
          class={"px-4 py-2 text-sm rounded-lg transition-colors " <> if @active_tab == elem(tab, 0), do: "bg-gray-700 text-white", else: "text-gray-400 hover:text-gray-200"}
        >
          {elem(tab, 1)}
        </button>
      </div>

      <%!-- Users tab --%>
      <div :if={@active_tab == "users"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-semibold text-white">User Management</h2>
          <button class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg">
            Add User
          </button>
        </div>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-gray-400 border-b border-gray-700">
              <th class="text-left py-2 px-4 font-medium">Name</th>
              <th class="text-left py-2 px-4 font-medium">Email</th>
              <th class="text-left py-2 px-4 font-medium">Role</th>
              <th class="text-left py-2 px-4 font-medium">Last Active</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={user <- @users} class="border-b border-gray-700/50">
              <td class="py-2 px-4 text-gray-200">{user.name}</td>
              <td class="py-2 px-4 text-gray-300">{user.email}</td>
              <td class="py-2 px-4">
                <span class={[
                  "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium",
                  user.role == "admin" && "bg-purple-900/60 text-purple-300",
                  user.role == "analyst" && "bg-blue-900/60 text-blue-300",
                  user.role == "viewer" && "bg-gray-700/60 text-gray-300"
                ]}>
                  {user.role}
                </span>
              </td>
              <td class="py-2 px-4 text-gray-400">{user.last_active}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <%!-- Enrollment tokens tab --%>
      <div :if={@active_tab == "tokens"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <div class="flex items-center justify-between mb-4">
          <h2 class="text-lg font-semibold text-white">Enrollment Tokens</h2>
          <button class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg">
            Generate Token
          </button>
        </div>
        <table class="w-full text-sm">
          <thead>
            <tr class="text-gray-400 border-b border-gray-700">
              <th class="text-left py-2 px-4 font-medium">Label</th>
              <th class="text-left py-2 px-4 font-medium">Token</th>
              <th class="text-left py-2 px-4 font-medium">Uses Remaining</th>
              <th class="text-left py-2 px-4 font-medium">Expires</th>
              <th class="text-left py-2 px-4 font-medium">Created By</th>
            </tr>
          </thead>
          <tbody>
            <tr :for={token <- @enrollment_tokens} class="border-b border-gray-700/50">
              <td class="py-2 px-4 text-gray-200">{token.label}</td>
              <td class="py-2 px-4 text-gray-400 font-mono text-xs">{token.token_preview}</td>
              <td class="py-2 px-4 text-gray-300">{token.uses_remaining || "unlimited"}</td>
              <td class="py-2 px-4 text-gray-400">{token.expires}</td>
              <td class="py-2 px-4 text-gray-300">{token.created_by}</td>
            </tr>
          </tbody>
        </table>
      </div>

      <%!-- Alerts tab --%>
      <div :if={@active_tab == "alerts"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Alert Integrations</h2>
        <p class="text-gray-400 text-sm">Configure webhooks for Slack, PagerDuty, and email alerts.</p>
        <div class="mt-4 text-gray-500 text-sm text-center py-8 border-2 border-dashed border-gray-700 rounded-lg">
          No integrations configured yet.
        </div>
      </div>

      <%!-- Retention tab --%>
      <div :if={@active_tab == "retention"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">Retention Settings</h2>
        <div class="space-y-4 max-w-lg">
          <div>
            <label class="block text-sm text-gray-300 mb-1">Event Retention Period</label>
            <select class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-2 w-full">
              <option>30 days</option>
              <option selected>90 days</option>
              <option>180 days</option>
              <option>365 days</option>
            </select>
          </div>
          <div>
            <label class="block text-sm text-gray-300 mb-1">Threat Retention Period</label>
            <select class="bg-gray-700 border border-gray-600 text-gray-200 text-sm rounded-lg px-3 py-2 w-full">
              <option>90 days</option>
              <option>180 days</option>
              <option selected>365 days</option>
              <option>Indefinite</option>
            </select>
          </div>
          <button class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg">
            Save Changes
          </button>
        </div>
      </div>

      <%!-- mTLS tab --%>
      <div :if={@active_tab == "mtls"} class="bg-gray-800 border border-gray-700 rounded-xl p-5">
        <h2 class="text-lg font-semibold text-white mb-4">mTLS CA Management</h2>
        <div class="bg-gray-900 rounded-lg p-4 space-y-3">
          <div class="flex justify-between text-sm">
            <span class="text-gray-400">CA Certificate</span>
            <span class="text-green-400">Valid</span>
          </div>
          <div class="flex justify-between text-sm">
            <span class="text-gray-400">Expires</span>
            <span class="text-gray-200">2027-03-17</span>
          </div>
          <div class="flex justify-between text-sm">
            <span class="text-gray-400">Issued Certificates</span>
            <span class="text-gray-200">153</span>
          </div>
        </div>
        <button class="mt-4 px-4 py-2 bg-red-700 hover:bg-red-600 text-white text-sm rounded-lg">
          Rotate CA
        </button>
      </div>
    </div>
    """
  end

  defp placeholder_users do
    [
      %{name: "Operator", email: "operator@riggs.local", role: "admin", last_active: "2m ago"},
      %{name: "Alice Chen", email: "achen@riggs.local", role: "analyst", last_active: "15m ago"},
      %{name: "Bob Kumar", email: "bkumar@riggs.local", role: "analyst", last_active: "1h ago"},
      %{name: "Carol White", email: "cwhite@riggs.local", role: "viewer", last_active: "3h ago"}
    ]
  end

  defp placeholder_tokens do
    [
      %{label: "NYC Office Deploy Batch 2", token_preview: "enrl_a1b2c3...d4e5", uses_remaining: 50, expires: "2026-04-17", created_by: "Operator"},
      %{label: "SF Office Initial", token_preview: "enrl_f6g7h8...i9j0", uses_remaining: nil, expires: "2026-06-01", created_by: "Operator"},
      %{label: "London Refresh", token_preview: "enrl_k1l2m3...n4o5", uses_remaining: 10, expires: "2026-03-30", created_by: "Alice Chen"}
    ]
  end
end
