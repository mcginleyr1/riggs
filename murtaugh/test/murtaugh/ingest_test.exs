defmodule Murtaugh.IngestTest do
  # Provisions a real TimescaleDB tenant database (outside the SQL sandbox).
  use ExUnit.Case

  alias Murtaugh.{ShardManager, Tenancy, TenantRepo}
  alias Murtaugh.Ingest.{AgentRegistry, EventIngester, StorylineIngester, VulnIngester}

  setup_all do
    cfg = Murtaugh.Repo.config()
    db = "murtaugh_tenant_test_#{System.unique_integer([:positive])}"

    shard = %Murtaugh.Org.Shard{
      id: Ecto.UUID.generate(),
      name: db,
      database_url:
        "postgres://#{cfg[:username]}:#{cfg[:password]}@#{cfg[:hostname]}:#{cfg[:port]}/#{db}",
      database_name: db,
      host: cfg[:hostname],
      pool_size: 2,
      retention_days: 7
    }

    assert [_ | _] = Tenancy.ensure_tenant_db(shard)

    on_exit(fn ->
      ShardManager.stop_repo(shard.id)

      Ecto.Adapters.SQL.Sandbox.unboxed_run(Murtaugh.Repo, fn ->
        Ecto.Adapters.SQL.query!(Murtaugh.Repo, "DROP DATABASE IF EXISTS #{db} WITH (FORCE)")
      end)
    end)

    %{shard: shard}
  end

  setup %{shard: shard} do
    agent_id = Ecto.UUID.generate()
    AgentRegistry.register(agent_id, shard, Ecto.UUID.generate())
    on_exit(fn -> AgentRegistry.forget(agent_id) end)
    %{agent_id: agent_id}
  end

  defp count(shard, table, agent_id) do
    Tenancy.with_tenant(shard, fn ->
      %{rows: [[n]]} =
        TenantRepo.query!("SELECT count(*) FROM #{table} WHERE agent_id = $1", [
          Ecto.UUID.dump!(agent_id)
        ])

      n
    end)
  end

  test "events are stored once and payload JSON is decoded", %{shard: shard, agent_id: agent_id} do
    event = %{
      event_id: Ecto.UUID.generate(),
      storyline_id: Ecto.UUID.generate(),
      event_type: "process_create",
      payload_json: ~s({"pid": 42}),
      process_context: %{pid: 42, name: "bash"}
    }

    assert {:ok, 1} = EventIngester.ingest_events(agent_id, [event])
    assert {:ok, 0} = EventIngester.ingest_events(agent_id, [event])
    assert count(shard, "events", agent_id) == 1
  end

  test "storylines and vuln findings upsert", %{shard: shard, agent_id: agent_id} do
    storyline = %{
      agent_id: agent_id,
      storyline_id: Ecto.UUID.generate(),
      root_pid: 1,
      root_process: "bash",
      root_path: "/bin/bash",
      status: nil,
      max_severity: nil,
      threat_count: nil,
      event_count: 1,
      process_tree_json: ~s({"pid": 1})
    }

    assert :ok = StorylineIngester.update_storyline(storyline)
    assert :ok = StorylineIngester.update_storyline(%{storyline | event_count: 2})
    assert count(shard, "storylines", agent_id) == 1

    finding = %{
      cve_id: "CVE-2024-0001",
      package_name: "openssl",
      package_version: "3.0.0",
      package_source: "brew",
      cvss_score: 9.8,
      severity: "critical",
      fixed_version: "3.0.1"
    }

    assert {:ok, 1} = VulnIngester.ingest_vuln_scan(%{agent_id: agent_id, findings: [finding]})
    assert count(shard, "vulnerabilities", agent_id) == 1
  end
end
