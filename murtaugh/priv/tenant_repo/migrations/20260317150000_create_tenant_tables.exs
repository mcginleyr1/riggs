defmodule Murtaugh.TenantRepo.Migrations.CreateTenantTables do
  use Ecto.Migration

  def change do
    # -- agents --
    create table(:agents, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :org_node_id, :binary_id, null: false
      add :hostname, :text, null: false
      add :os, :text, null: false
      add :os_version, :text
      add :arch, :text
      add :agent_version, :text, null: false
      add :ip_address, :text
      add :mac_address, :text
      add :status, :text, null: false, default: "unknown"
      add :last_heartbeat, :utc_datetime
      add :enrolled_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :config_version, :integer, null: false, default: 0
      add :tags, {:array, :text}, default: []
      add :metadata, :map, default: %{}

      add :events_processed, :bigint, default: 0
      add :threats_detected, :bigint, default: 0
      add :dlp_blocks, :bigint, default: 0
      add :sensor_healthy, :boolean, default: true
      add :pipeline_latency_us, :bigint, default: 0
      add :store_size_bytes, :bigint, default: 0
      add :uptime_secs, :bigint, default: 0
    end

    create index(:agents, [:org_node_id])
    create index(:agents, [:status])
    create index(:agents, [:last_heartbeat])
    create index(:agents, [:tags], using: :gin)

    # -- events (regular table, no PARTITION BY) --
    create table(:events, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :storyline_id, :binary_id, null: false
      add :event_type, :text, null: false
      add :severity, :text, null: false
      # Part of the primary key: TimescaleDB requires the hypertable partition
      # column (timestamp) to be included in every unique index / primary key.
      add :timestamp, :utc_datetime, null: false, primary_key: true
      add :received_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :pid, :integer
      add :ppid, :integer
      add :process_name, :text
      add :process_path, :text
      add :cmdline, :text
      add :username, :text
      add :payload, :map, null: false
    end

    create index(:events, [:agent_id, :timestamp])
    create index(:events, [:org_node_id, :timestamp])
    create index(:events, [:storyline_id, :timestamp])
    create index(:events, [:event_type, :timestamp])

    create index(:events, [:severity, :timestamp],
      where: "severity != 'info'"
    )

    create index(:events, [:process_name, :timestamp],
      where: "process_name IS NOT NULL"
    )

    # -- threats --
    create table(:threats, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :event_id, :binary_id, null: false
      add :storyline_id, :binary_id, null: false
      add :threat_level, :text, null: false
      add :final_score, :float, null: false
      add :status, :text, null: false, default: "open"
      add :assigned_to_email, :text
      add :resolved_at, :utc_datetime
      add :resolution_note, :text
      add :timestamp, :utc_datetime, null: false
      add :received_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :verdicts, :map, null: false
      add :process_name, :text
      add :process_path, :text
      add :summary, :text
    end

    create index(:threats, [:agent_id, :timestamp])
    create index(:threats, [:org_node_id, :timestamp])
    create index(:threats, [:status, :threat_level, :timestamp])
    create index(:threats, [:storyline_id])

    # -- storylines --
    create table(:storylines, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :root_pid, :integer
      add :root_process, :text
      add :root_path, :text
      add :status, :text, null: false, default: "active"
      add :max_severity, :text, null: false, default: "info"
      add :threat_count, :integer, null: false, default: 0
      add :event_count, :integer, null: false, default: 0
      add :first_seen, :utc_datetime, null: false
      add :last_seen, :utc_datetime, null: false
      add :process_tree, :map
    end

    create index(:storylines, [:agent_id, :last_seen])
    create index(:storylines, [:org_node_id, :last_seen])

    create index(:storylines, [:max_severity, :last_seen],
      where: "max_severity != 'info'"
    )

    # -- dlp_events --
    create table(:dlp_events, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :timestamp, :utc_datetime, null: false
      add :received_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :action, :text, null: false
      add :pid, :integer, null: false
      add :process_name, :text, null: false
      add :file_path, :text, null: false
      add :file_type, :text, null: false
      add :domain, :text, null: false
      add :domain_category, :text
      add :username, :text
    end

    create index(:dlp_events, [:agent_id, :timestamp])
    create index(:dlp_events, [:org_node_id, :timestamp])
    create index(:dlp_events, [:action, :timestamp])
    create index(:dlp_events, [:domain, :timestamp])

    # -- response_actions --
    create table(:response_actions, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :threat_id, :binary_id
      add :action_type, :text, null: false
      add :target, :text, null: false
      add :initiated_by, :text, null: false
      add :success, :boolean, null: false
      add :detail, :text
      add :timestamp, :utc_datetime, null: false, default: fragment("NOW()")
    end

    create index(:response_actions, [:agent_id, :timestamp])

    # -- vulnerabilities --
    create table(:vulnerabilities, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :cve_id, :text, null: false
      add :package_name, :text, null: false
      add :package_version, :text, null: false
      add :package_source, :text
      add :cvss_score, :float
      add :severity, :text, null: false
      add :fixed_version, :text
      add :scan_timestamp, :utc_datetime, null: false
      add :status, :text, null: false, default: "open"
    end

    create unique_index(:vulnerabilities, [:agent_id, :cve_id, :package_name])
    create index(:vulnerabilities, [:agent_id])
    create index(:vulnerabilities, [:org_node_id])
    create index(:vulnerabilities, [:severity, :cvss_score])

    # -- device_events --
    create table(:device_events, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :timestamp, :utc_datetime, null: false
      add :device_type, :text, null: false
      add :action, :text, null: false
      add :vendor_id, :integer
      add :product_id, :integer
      add :serial_number, :text
      add :device_class, :text
      add :manufacturer, :text
      add :product_name, :text
      add :policy_decision, :text, null: false
    end

    create index(:device_events, [:agent_id, :timestamp])
    create index(:device_events, [:org_node_id, :timestamp])

    # -- network_hosts --
    create table(:network_hosts, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :org_node_id, :binary_id, null: false
      add :ip_address, :text, null: false
      add :mac_address, :text
      add :hostname, :text
      add :vendor, :text
      add :first_seen, :utc_datetime, null: false
      add :last_seen, :utc_datetime, null: false
      add :is_internal, :boolean, null: false, default: true
      add :open_ports, {:array, :integer}, default: []
    end

    create unique_index(:network_hosts, [:agent_id, :ip_address])
    create index(:network_hosts, [:agent_id])
    create index(:network_hosts, [:org_node_id])

    # -- applied_policies --
    create table(:applied_policies, primary_key: false) do
      add :id, :binary_id, primary_key: true, default: fragment("gen_random_uuid()")
      add :agent_id, :binary_id, null: false
      add :policy_type, :text, null: false
      add :policy_name, :text, null: false
      add :content_hash, :text, null: false
      add :version, :integer, null: false
      add :applied_at, :utc_datetime, null: false, default: fragment("NOW()")
      add :status, :text, null: false, default: "pending"
    end

    create unique_index(:applied_policies, [:agent_id, :policy_type])
  end
end
