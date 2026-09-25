defmodule Murtaugh.TenantRepo do
  @moduledoc """
  Repo for per-tenant databases. Started dynamically per shard by ShardManager,
  not in the supervision tree; use put_dynamic_repo/1 to route to a shard.
  """
  use Ecto.Repo,
    otp_app: :murtaugh,
    adapter: Ecto.Adapters.Postgres
end
