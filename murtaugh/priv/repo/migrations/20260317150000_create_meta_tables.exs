defmodule Murtaugh.Repo.Migrations.CreateMetaTables do
  use Ecto.Migration

  def change do
    # -------------------------------------------------------------------
    # tenant_shards — must exist before org_nodes references it
    # -------------------------------------------------------------------
    create table(:tenant_shards, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :text, null: false
      add :database_url, :text, null: false
      add :database_name, :text, null: false
      add :host, :text, null: false
      add :port, :integer, null: false, default: 5432
      add :pool_size, :integer, null: false, default: 10
      add :status, :text, null: false, default: "active"
      add :retention_days, :integer, null: false, default: 90
      add :archive_enabled, :boolean, null: false, default: false
      add :archive_retention_days, :integer, null: false, default: 365

      timestamps(type: :utc_datetime)
    end

    create unique_index(:tenant_shards, [:name])

    # -------------------------------------------------------------------
    # org_nodes — nested set tree
    # -------------------------------------------------------------------
    create table(:org_nodes, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :parent_id, references(:org_nodes, type: :binary_id, on_delete: :nilify_all)
      add :node_type, :text, null: false
      add :name, :text, null: false
      add :slug, :text, null: false
      add :description, :text

      add :lft, :integer, null: false
      add :rgt, :integer, null: false
      add :depth, :integer, null: false, default: 0

      add :tenant_shard_id, references(:tenant_shards, type: :binary_id, on_delete: :nilify_all)

      add :metadata, :map, default: %{}

      timestamps(type: :utc_datetime)
    end

    create unique_index(:org_nodes, [:lft])
    create unique_index(:org_nodes, [:rgt])
    create unique_index(:org_nodes, [:slug])
    create index(:org_nodes, [:parent_id])
    create index(:org_nodes, [:node_type])
    create index(:org_nodes, [:tenant_shard_id], where: "tenant_shard_id IS NOT NULL")

    # -------------------------------------------------------------------
    # users
    # -------------------------------------------------------------------
    create table(:users, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :email, :text, null: false
      add :name, :text, null: false
      add :password_hash, :text, null: false
      add :is_superadmin, :boolean, null: false, default: false

      timestamps(type: :utc_datetime)
    end

    create unique_index(:users, [:email])

    # -------------------------------------------------------------------
    # user_grants
    # -------------------------------------------------------------------
    create table(:user_grants, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :delete_all), null: false

      add :org_node_id, references(:org_nodes, type: :binary_id, on_delete: :delete_all),
        null: false

      add :role, :text, null: false

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:user_grants, [:user_id, :org_node_id])
    create index(:user_grants, [:user_id])
    create index(:user_grants, [:org_node_id])

    # -------------------------------------------------------------------
    # enrollment_tokens
    # -------------------------------------------------------------------
    create table(:enrollment_tokens, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :org_node_id, references(:org_nodes, type: :binary_id, on_delete: :delete_all),
        null: false

      add :token, :text, null: false
      add :label, :text
      add :uses_remaining, :integer
      add :expires_at, :utc_datetime
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create unique_index(:enrollment_tokens, [:token])
    create index(:enrollment_tokens, [:org_node_id])

    # -------------------------------------------------------------------
    # policy_templates
    # -------------------------------------------------------------------
    create table(:policy_templates, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :name, :text, null: false
      add :policy_type, :text, null: false
      add :content, :text, null: false
      add :version, :integer, null: false, default: 1
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all)

      timestamps(type: :utc_datetime)
    end

    create unique_index(:policy_templates, [:name])

    # -------------------------------------------------------------------
    # alert_integrations
    # -------------------------------------------------------------------
    create table(:alert_integrations, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :org_node_id, references(:org_nodes, type: :binary_id, on_delete: :delete_all),
        null: false

      add :integration_type, :text, null: false
      add :name, :text, null: false
      add :config, :map, null: false
      add :enabled, :boolean, null: false, default: true
      add :severity_filter, {:array, :text}, default: ["suspicious", "malicious"]

      timestamps(type: :utc_datetime)
    end

    create index(:alert_integrations, [:org_node_id])

    # -------------------------------------------------------------------
    # audit_log
    # -------------------------------------------------------------------
    create table(:audit_log, primary_key: false) do
      add :id, :binary_id, primary_key: true
      add :user_id, references(:users, type: :binary_id, on_delete: :nilify_all)
      add :org_node_id, references(:org_nodes, type: :binary_id, on_delete: :nilify_all)
      add :action, :text, null: false
      add :target_type, :text
      add :target_id, :binary_id
      add :detail, :map
      add :timestamp, :utc_datetime, null: false
    end

    create index(:audit_log, [:user_id, :timestamp])
    create index(:audit_log, [:org_node_id, :timestamp])

    # -------------------------------------------------------------------
    # archive_manifests
    # -------------------------------------------------------------------
    create table(:archive_manifests, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :tenant_shard_id, references(:tenant_shards, type: :binary_id, on_delete: :delete_all),
        null: false

      add :table_name, :text, null: false
      add :year_month, :text, null: false
      add :object_key, :text, null: false
      add :file_size_bytes, :bigint, null: false
      add :row_count, :bigint, null: false
      add :checksum, :text, null: false
      add :status, :text, null: false, default: "pending"

      timestamps(type: :utc_datetime)
    end

    create index(:archive_manifests, [:tenant_shard_id])
    create unique_index(:archive_manifests, [:tenant_shard_id, :table_name, :year_month])

    # -------------------------------------------------------------------
    # legal_holds
    # -------------------------------------------------------------------
    create table(:legal_holds, primary_key: false) do
      add :id, :binary_id, primary_key: true

      add :org_node_id, references(:org_nodes, type: :binary_id, on_delete: :restrict),
        null: false

      add :reason, :text, null: false
      add :created_by, references(:users, type: :binary_id, on_delete: :nilify_all), null: false
      add :active, :boolean, null: false, default: true
      add :released_at, :utc_datetime

      timestamps(type: :utc_datetime)
    end

    create index(:legal_holds, [:org_node_id])
    create index(:legal_holds, [:active], where: "active = true")
  end
end
