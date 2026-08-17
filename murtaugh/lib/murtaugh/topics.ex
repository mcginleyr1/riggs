defmodule Murtaugh.Topics do
  @moduledoc """
  Per-org PubSub topic names.

  Ingesters broadcast on the org-node the agent belongs to; LiveViews subscribe
  on the org they are currently viewing. Scoping by org id keeps a tenant's
  real-time threat/DLP/fleet stream from leaking into another tenant's console.

  Note: topics are keyed by the exact org-node id. A user viewing a parent node
  does not receive descendant nodes' events (hierarchical roll-up would be a
  separate enhancement); the security property here is that no cross-org events
  are ever delivered.
  """

  def threats(org_id), do: "threats:#{org_id}"
  def dlp(org_id), do: "dlp:#{org_id}"
  def fleet(org_id), do: "fleet:#{org_id}"
  def throughput(org_id), do: "throughput:#{org_id}"
end
