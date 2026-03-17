defmodule MurtaughWeb.DlpPoliciesLive do
  use MurtaughWeb, :live_view

  @impl true
  def mount(_params, _session, socket) do
    socket =
      socket
      |> assign(:page_title, "DLP Policies")
      |> assign(:policies, placeholder_policies())
      |> assign(:selected_policy, nil)

    {:ok, socket}
  end

  @impl true
  def handle_event("select_policy", %{"id" => id}, socket) do
    policy = Enum.find(socket.assigns.policies, &(&1.id == id))
    {:noreply, assign(socket, :selected_policy, policy)}
  end

  def handle_event("close_detail", _params, socket) do
    {:noreply, assign(socket, :selected_policy, nil)}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <div class="space-y-6">
      <div class="flex items-center justify-between">
        <div>
          <.link navigate={~p"/orgs/#{@org_slug}/dlp"} class="text-gray-400 hover:text-gray-200 text-sm">
            <span class="hero-arrow-left size-4" /> Back to DLP
          </.link>
          <h1 class="text-2xl font-bold text-white mt-1">DLP Policies</h1>
        </div>
        <button class="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-sm rounded-lg">
          Create Policy
        </button>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <%!-- Policy list --%>
        <div class="lg:col-span-2 bg-gray-800 border border-gray-700 rounded-xl overflow-hidden">
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="text-gray-400 border-b border-gray-700 bg-gray-800/80">
                  <th class="text-left py-3 px-4 font-medium">Name</th>
                  <th class="text-left py-3 px-4 font-medium">Type</th>
                  <th class="text-left py-3 px-4 font-medium">Version</th>
                  <th class="text-left py-3 px-4 font-medium">Agents</th>
                  <th class="text-left py-3 px-4 font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                <tr
                  :for={policy <- @policies}
                  class={"border-b border-gray-700/50 hover:bg-gray-700/30 cursor-pointer " <> if @selected_policy && @selected_policy.id == policy.id, do: "bg-gray-700/40", else: ""}
                  phx-click="select_policy"
                  phx-value-id={policy.id}
                >
                  <td class="py-3 px-4 text-gray-200 font-medium">{policy.name}</td>
                  <td class="py-3 px-4">
                    <span class="inline-flex items-center px-2 py-0.5 rounded text-xs font-mono bg-gray-700 text-gray-300">
                      {policy.type}
                    </span>
                  </td>
                  <td class="py-3 px-4 text-gray-400 font-mono">v{policy.version}</td>
                  <td class="py-3 px-4 text-gray-300">{policy.agent_count}</td>
                  <td class="py-3 px-4">
                    <span class={[
                      "inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium",
                      policy.active && "bg-green-900/60 text-green-300",
                      !policy.active && "bg-gray-700/60 text-gray-400"
                    ]}>
                      {if policy.active, do: "active", else: "disabled"}
                    </span>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>

        <%!-- Policy detail --%>
        <div class="bg-gray-800 border border-gray-700 rounded-xl p-5">
          <div :if={@selected_policy == nil} class="text-gray-500 text-sm text-center py-12">
            Select a policy to view details
          </div>
          <div :if={@selected_policy}>
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-lg font-semibold text-white">{@selected_policy.name}</h2>
              <button phx-click="close_detail" class="text-gray-400 hover:text-gray-200">
                <span class="hero-x-mark size-5" />
              </button>
            </div>
            <p class="text-sm text-gray-400 mb-4">{@selected_policy.description}</p>
            <div class="bg-gray-950 rounded-lg p-4 font-mono text-xs text-gray-300 overflow-x-auto">
              <pre>{@selected_policy.content}</pre>
            </div>
          </div>
        </div>
      </div>
    </div>
    """
  end

  defp placeholder_policies do
    [
      %{id: "p1", name: "No Paste Sites", type: "domain_block", version: "3", agent_count: 142, active: true,
        description: "Blocks uploads to paste sites and anonymous file sharing services.",
        content: "[policy]\nname = \"No Paste Sites\"\naction = \"block\"\n\n[[rules]]\ndomains = [\n  \"paste.ee\",\n  \"pastebin.com\",\n  \"anonfiles.com\",\n  \"transfer.sh\"\n]"},
      %{id: "p2", name: "No Cloud Storage", type: "domain_block", version: "5", agent_count: 142, active: true,
        description: "Blocks file uploads to consumer cloud storage providers.",
        content: "[policy]\nname = \"No Cloud Storage\"\naction = \"block\"\n\n[[rules]]\ndomains = [\n  \"dropbox.com\",\n  \"mega.nz\",\n  \"box.com\",\n  \"onedrive.live.com\"\n]"},
      %{id: "p3", name: "Monitor Cloud Storage", type: "domain_alert", version: "2", agent_count: 45, active: true,
        description: "Alerts on file uploads to approved cloud storage without blocking.",
        content: "[policy]\nname = \"Monitor Cloud Storage\"\naction = \"alert\"\n\n[[rules]]\ndomains = [\n  \"drive.google.com\",\n  \"sharepoint.com\"\n]"},
      %{id: "p4", name: "Monitor Messaging", type: "domain_alert", version: "1", agent_count: 142, active: true,
        description: "Alerts on file uploads via messaging platforms.",
        content: "[policy]\nname = \"Monitor Messaging\"\naction = \"alert\"\n\n[[rules]]\ndomains = [\"slack.com\", \"teams.microsoft.com\"]"},
      %{id: "p5", name: "Block PII Upload", type: "content_scan", version: "1", agent_count: 0, active: false,
        description: "Scans outbound content for PII patterns (SSN, credit card, etc).",
        content: "[policy]\nname = \"Block PII Upload\"\naction = \"block\"\n\n[[rules.patterns]]\nname = \"SSN\"\nregex = \"\\\\d{3}-\\\\d{2}-\\\\d{4}\""}
    ]
  end
end
