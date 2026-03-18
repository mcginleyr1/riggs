defmodule Murtaugh.Repo.Migrations.EnableTimescaledb do
  use Ecto.Migration

  def up do
    execute "CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE"
  end

  def down do
    # TimescaleDB cannot be dropped if hypertables exist.
    # Intentionally a no-op on rollback.
    :ok
  end
end
