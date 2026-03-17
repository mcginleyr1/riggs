defmodule Murtaugh.Ingest.VulnIngester do
  @moduledoc "Upserts vulnerability findings into the tenant vulnerabilities table."

  alias Murtaugh.{Tenancy, TenantRepo}
  alias Murtaugh.Ingest.AgentRegistry

  def ingest_vuln_scan(report) do
    case AgentRegistry.lookup(report.agent_id) do
      {:ok, shard, org_node_id} ->
        Tenancy.with_tenant(shard, fn ->
          now = DateTime.utc_now() |> DateTime.truncate(:second)

          rows =
            Enum.map(report.findings || [], fn f ->
              %{
                id: Ecto.UUID.generate(),
                agent_id: report.agent_id,
                org_node_id: org_node_id,
                cve_id: f.cve_id,
                package_name: f.package_name,
                package_version: f.package_version,
                package_source: f.package_source,
                cvss_score: f.cvss_score,
                severity: f.severity,
                fixed_version: f.fixed_version,
                scan_timestamp: now,
                status: "open"
              }
            end)

          {count, _} =
            TenantRepo.insert_all("vulnerabilities", rows,
              on_conflict: {:replace, [:package_version, :cvss_score, :severity, :fixed_version, :scan_timestamp]},
              conflict_target: [:agent_id, :cve_id, :package_name]
            )

          {:ok, count}
        end)

      :error ->
        {:error, :unknown_agent}
    end
  end
end
