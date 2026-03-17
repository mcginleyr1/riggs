defmodule Murtaugh.TenantRepo do
  use Ecto.Repo,
    otp_app: :murtaugh,
    adapter: Ecto.Adapters.Postgres

  # Started dynamically per-shard by ShardManager, not in the supervision tree.
  # Use Ecto.Repo.put_dynamic_repo/1 to route queries to a specific shard.
end
