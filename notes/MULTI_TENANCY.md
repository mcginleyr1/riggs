# Murtaugh — Multi-Tenancy & Org Hierarchy

## Naming

- **Riggs** = the endpoint agent
- **Murtaugh** = the management console
- Thematic: Riggs is the loose cannon in the field, Murtaugh is the
  experienced partner watching the bigger picture from the desk.

## The Problem

A flat agents → events model doesn't work for:
- MSSPs managing multiple clients
- Enterprises with sites, regions, departments
- Compliance requiring physical data separation between tenants
- Event tables that grow to billions of rows

We need:
1. A flexible organizational hierarchy (n-ary tree with typed nodes)
2. Physical database separation per tenant
3. A single metadata database for auth, routing, and the org tree
4. Time-partitioned event storage within each tenant DB

## Architecture: Two-Tier Database

```
┌──────────────────────────────────────────────────┐
│              murtaugh_meta (PostgreSQL)           │
│                                                    │
│  org_nodes (nested set tree)                       │
│  users + roles + permissions                       │
│  tenant_shards (tenant → connection mapping)       │
│  enrollment_tokens                                 │
│  audit_log (global)                                │
│  policies (templates)                              │
│  alert_integrations                                │
└─────────────────────┬────────────────────────────┘
                      │ routes to
          ┌───────────┼───────────────┐
          ▼           ▼               ▼
┌─────────────┐ ┌─────────────┐ ┌─────────────┐
│ tenant_abc  │ │ tenant_def  │ │ tenant_ghi  │
│ (PostgreSQL)│ │ (PostgreSQL)│ │ (PostgreSQL)│
│             │ │             │ │             │
│ agents      │ │ agents      │ │ agents      │
│ events      │ │ events      │ │ events      │
│ threats     │ │ threats     │ │ threats     │
│ storylines  │ │ storylines  │ │ storylines  │
│ dlp_events  │ │ dlp_events  │ │ dlp_events  │
│ response_*  │ │ response_*  │ │ response_*  │
│ vuln_*      │ │ vuln_*      │ │ vuln_*      │
│ devices_*   │ │ devices_*   │ │ devices_*   │
│ network_*   │ │ network_*   │ │ network_*   │
└─────────────┘ └─────────────┘ └─────────────┘
```

**Physical separation**: each tenant's data lives in its own PostgreSQL
database (could be on the same server, a different server, or a different
cloud region). A tenant never sees another tenant's data because they're
in entirely different databases.

**Single metadata DB**: auth, the org tree, and tenant→shard routing live
in one central database. This is the only DB Murtaugh connects to at
startup. Tenant DBs are connected on-demand when a user navigates to
tenant-scoped data.

## Org Tree: Nested Set Model

### Why Nested Set

The org hierarchy is an n-ary tree with typed nodes. Common queries:
- "Give me all agents under Client A" (subtree query)
- "What's the path from this agent to the root?" (ancestry query)
- "Which nodes is this user allowed to see?" (permission scoping)

Nested set makes subtree queries a single range scan:
```sql
-- All descendants of node X:
SELECT * FROM org_nodes WHERE lft > X.lft AND rgt < X.rgt;

-- All ancestors of node X:
SELECT * FROM org_nodes WHERE lft < X.lft AND rgt > X.rgt ORDER BY lft;
```

No recursive CTEs, no closure tables, just integer comparisons.

### Node Types

The tree is heterogeneous — each node has a `node_type` that determines
its role in the hierarchy:

```
root (type: root)
├── Acme Corp (type: account)
│   ├── US Operations (type: region)
│   │   ├── NYC Office (type: site)
│   │   │   ├── Engineering (type: group)
│   │   │   └── Sales (type: group)
│   │   └── SF Office (type: site)
│   └── EU Operations (type: region)
│       └── London Office (type: site)
├── Globex Inc (type: account)
│   ├── HQ (type: site)
│   └── Remote (type: group)
└── Internal (type: account)
    └── SOC Team (type: group)
```

Node types are open-ended (user-definable), but the system ships with:

| Type | Meaning | Typical Use |
|---|---|---|
| `root` | Tree root (exactly one) | System-level |
| `account` | Tenant/client | MSSP client, enterprise division |
| `region` | Geographic grouping | US, EU, APAC |
| `site` | Physical location | Office, datacenter |
| `group` | Logical grouping | Department, team, fleet segment |

### Schema: org_nodes

```sql
-- In murtaugh_meta database

CREATE TABLE org_nodes (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id   UUID REFERENCES org_nodes(id),
    node_type   TEXT NOT NULL,             -- root, account, region, site, group
    name        TEXT NOT NULL,
    slug        TEXT NOT NULL,             -- url-friendly: "acme-corp", "nyc-office"
    description TEXT,

    -- nested set fields
    lft         INTEGER NOT NULL,
    rgt         INTEGER NOT NULL,
    depth       INTEGER NOT NULL DEFAULT 0,

    -- tenant shard reference (only set on account-level nodes)
    -- all descendants of this node use the same shard
    tenant_shard_id UUID REFERENCES tenant_shards(id),

    metadata    JSONB DEFAULT '{}',        -- extensible per-type data
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_org_nodes_lft ON org_nodes (lft);
CREATE UNIQUE INDEX idx_org_nodes_rgt ON org_nodes (rgt);
CREATE INDEX idx_org_nodes_parent ON org_nodes (parent_id);
CREATE INDEX idx_org_nodes_type ON org_nodes (node_type);
CREATE INDEX idx_org_nodes_slug ON org_nodes (slug);
CREATE INDEX idx_org_nodes_shard ON org_nodes (tenant_shard_id);
```

### Schema: tenant_shards

Maps tenants to their physical database.

```sql
CREATE TABLE tenant_shards (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,       -- "shard-acme", "shard-globex"
    database_url    TEXT NOT NULL,              -- postgres://...
    database_name   TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL DEFAULT 5432,
    pool_size       INTEGER NOT NULL DEFAULT 10,
    status          TEXT NOT NULL DEFAULT 'active', -- active, migrating, archived
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### Shard Resolution

Every request in Murtaugh flows through a tenant context:

```
User request
    │
    ▼
Authenticate user (meta DB)
    │
    ▼
Determine current org_node (from URL: /orgs/:slug/...)
    │
    ▼
Walk up tree to find nearest ancestor with tenant_shard_id
    │
    ▼
Look up tenant_shards row → get database_url
    │
    ▼
Get or create Ecto dynamic repo for that shard
    │
    ▼
Execute query against tenant DB
```

In Elixir:

```elixir
defmodule Murtaugh.Tenancy do
  @doc """
  Resolves the tenant shard for an org node.
  Walks up the tree to find the account node with a shard assignment.
  """
  def resolve_shard(%OrgNode{} = node) do
    # Nested set ancestor query
    ancestors = Repo.all(
      from n in OrgNode,
        where: n.lft < ^node.lft and n.rgt > ^node.rgt,
        where: not is_nil(n.tenant_shard_id),
        order_by: [desc: n.lft],
        limit: 1,
        preload: [:tenant_shard]
    )

    case ancestors do
      [ancestor] -> {:ok, ancestor.tenant_shard}
      [] ->
        if node.tenant_shard_id do
          {:ok, Repo.preload(node, :tenant_shard).tenant_shard}
        else
          {:error, :no_shard}
        end
    end
  end
end
```

### Dynamic Repos

Ecto supports dynamic repos via `Ecto.Repo.put_dynamic_repo/1`. Each
tenant shard gets its own repo process pool:

```elixir
defmodule Murtaugh.TenantRepo do
  use Ecto.Repo,
    otp_app: :murtaugh,
    adapter: Ecto.Adapters.Postgres

  # This repo is started dynamically per-shard, not in the supervision tree
end

defmodule Murtaugh.ShardManager do
  use GenServer

  # Caches active repo pids keyed by shard_id
  # Starts a new TenantRepo process pool for a shard on first access
  # Shuts down idle pools after 30 minutes

  def get_repo(shard_id) do
    GenServer.call(__MODULE__, {:get_repo, shard_id})
  end

  def handle_call({:get_repo, shard_id}, _from, state) do
    case Map.get(state.repos, shard_id) do
      nil ->
        shard = Murtaugh.Repo.get!(TenantShard, shard_id)
        {:ok, pid} = TenantRepo.start_link(
          name: nil,
          url: shard.database_url,
          pool_size: shard.pool_size
        )
        new_state = put_in(state.repos[shard_id], pid)
        {:reply, {:ok, pid}, new_state}
      pid ->
        {:reply, {:ok, pid}, state}
    end
  end
end
```

Usage in a context:

```elixir
defmodule Murtaugh.Telemetry do
  def list_events(tenant_shard, opts \\ []) do
    {:ok, repo} = ShardManager.get_repo(tenant_shard.id)
    TenantRepo.put_dynamic_repo(repo)

    TenantRepo.all(
      from e in Event,
        order_by: [desc: e.timestamp],
        limit: ^Keyword.get(opts, :limit, 50)
    )
  end
end
```

## Agent-to-Org-Node Binding

Agents are bound to org nodes. An agent at "NYC Office" is visible to
anyone with access to NYC Office, US Operations, Acme Corp, or root.

```sql
-- In each tenant DB:
CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_node_id     UUID NOT NULL,           -- references org_nodes.id in meta DB
    hostname        TEXT NOT NULL,
    -- ... rest of agent fields
);
```

The `org_node_id` is a cross-database reference (UUID, not a foreign key).
The agent enrollment flow:
1. Agent connects with enrollment token
2. Token is scoped to an org node (e.g., "NYC Office")
3. Agent record is created in the tenant DB associated with that org node
4. Agent's `org_node_id` is set to the org node from the token

## User Permissions

Users are granted access at org node level. Access cascades down the tree.

```sql
-- In murtaugh_meta database

CREATE TABLE user_grants (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    org_node_id UUID NOT NULL REFERENCES org_nodes(id),
    role        TEXT NOT NULL,             -- admin, analyst, viewer
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (user_id, org_node_id)
);
```

A user with `analyst` role on "US Operations" can see everything under
US Operations (NYC Office, SF Office, and all their agents/events) but
nothing under EU Operations.

Permission check:

```elixir
def user_can_access?(user, target_node) do
  grants = Repo.all(
    from g in UserGrant,
      join: n in OrgNode, on: n.id == g.org_node_id,
      where: g.user_id == ^user.id,
      # Grant node is an ancestor of target (or is the target itself)
      where: n.lft <= ^target_node.lft and n.rgt >= ^target_node.rgt
  )
  length(grants) > 0
end
```

## Event & Threat Scaling (Within Tenant DB)

Even within a single tenant DB, events need partitioning.

### Time-Based Partitioning

```sql
-- In each tenant DB:

CREATE TABLE events (
    id              UUID NOT NULL,
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    storyline_id    UUID NOT NULL,
    event_type      TEXT NOT NULL,
    severity        TEXT NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    pid             INTEGER,
    process_name    TEXT,
    process_path    TEXT,
    payload         JSONB NOT NULL,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Monthly partitions
CREATE TABLE events_2026_03 PARTITION OF events
    FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');
CREATE TABLE events_2026_04 PARTITION OF events
    FOR VALUES FROM ('2026-04-01') TO ('2026-05-01');
```

### Org-Node Scoped Queries

Since events carry `org_node_id`, queries for a subtree use the nested
set range from the meta DB:

```elixir
def list_events_for_node(tenant_shard, org_node, opts) do
  # Get all descendant node IDs from meta DB
  descendant_ids = Murtaugh.Org.descendant_ids(org_node)

  {:ok, repo} = ShardManager.get_repo(tenant_shard.id)
  TenantRepo.put_dynamic_repo(repo)

  TenantRepo.all(
    from e in Event,
      where: e.org_node_id in ^descendant_ids,
      where: e.timestamp >= ^opts[:from],
      where: e.timestamp <= ^opts[:to],
      order_by: [desc: e.timestamp],
      limit: ^opts[:limit]
  )
end
```

The partition pruning kicks in on the `timestamp` filter, and the
`org_node_id` index narrows within the partition.

### Threats Table

Same approach — partitioned by time, indexed by org_node_id and status:

```sql
CREATE TABLE threats (
    id              UUID NOT NULL,
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    event_id        UUID NOT NULL,
    storyline_id    UUID NOT NULL,
    threat_level    TEXT NOT NULL,
    final_score     REAL NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',
    timestamp       TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verdicts        JSONB NOT NULL,
    process_name    TEXT,
    summary         TEXT,
    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);
```

### Retention

An Oban worker runs daily per tenant:
1. Drops partitions older than the tenant's retention policy
2. Creates next month's partition if it doesn't exist
3. Logs partition maintenance to audit

## Enrollment Tokens

Scoped to org nodes, stored in meta DB:

```sql
CREATE TABLE enrollment_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_node_id UUID NOT NULL REFERENCES org_nodes(id),
    token       TEXT NOT NULL UNIQUE,      -- random 32-byte hex
    label       TEXT,                       -- "NYC office deploy batch 2"
    uses_remaining INTEGER,                 -- null = unlimited
    expires_at  TIMESTAMPTZ,
    created_by  UUID REFERENCES users(id),
    inserted_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

When an agent enrolls with a token:
1. Look up token in meta DB → get org_node_id
2. Resolve tenant shard from org_node_id
3. Create agent record in tenant DB with org_node_id
4. Decrement uses_remaining (if not null)
5. Return agent_id + mTLS certs

## Summary

| Concern | Solution |
|---|---|
| Org hierarchy | N-ary tree with nested set in meta DB |
| Node types | Open-ended: root, account, region, site, group |
| Physical data separation | Database-per-tenant, connection info in meta DB |
| Shard routing | Walk org tree to account node → lookup shard → dynamic Ecto repo |
| Event scaling | Time-partitioned tables within each tenant DB |
| Permissions | User grants at org node level, cascade down via nested set |
| Agent enrollment | Token scoped to org node, resolves shard, creates agent in tenant DB |
