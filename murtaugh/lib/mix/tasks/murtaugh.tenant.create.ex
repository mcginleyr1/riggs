defmodule Mix.Tasks.Murtaugh.Tenant.Create do
  @moduledoc """
  Provisions a new tenant: account org node, shard and database.

      mix murtaugh.tenant.create "Acme Corp" acme
      mix murtaugh.tenant.create "Acme Corp" acme --retention-days 30
  """
  use Mix.Task

  @shortdoc "Provision a new tenant (org node, shard, database)"

  @impl true
  def run(args) do
    {opts, [name, slug], _} = OptionParser.parse(args, strict: [retention_days: :integer])
    Mix.Task.run("app.start")

    case Murtaugh.Tenancy.create_tenant(%{
           name: name,
           slug: slug,
           retention_days: opts[:retention_days]
         }) do
      {:ok, %{shard: shard}} ->
        Mix.shell().info("Provisioned tenant #{slug} (database #{shard.database_name})")

      {:error, changeset} ->
        Mix.raise("Could not create tenant: #{inspect(changeset.errors)}")
    end
  end
end
