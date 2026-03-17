# Murtaugh — Data Model

## Two-Tier Database Architecture

**Meta DB** (`murtaugh_meta`): org tree, users, permissions, shard routing,
enrollment tokens, global audit log, policy templates, alert integrations.

**Tenant DBs** (`murtaugh_tenant_<slug>`): one per account-level org node.
Contains all operational data: agents, events, threats, DLP events,
storylines, response actions, vulnerabilities, device events, network hosts,
applied policies.

## Meta DB Schema

### org_nodes (nested set tree)

```sql
CREATE TABLE org_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    parent_id       UUID REFERENCES org_nodes(id),
    node_type       TEXT NOT NULL,            -- root, account, region, site, group
    name            TEXT NOT NULL,
    slug            TEXT NOT NULL UNIQUE,
    description     TEXT,

    -- nested set
    lft             INTEGER NOT NULL,
    rgt             INTEGER NOT NULL,
    depth           INTEGER NOT NULL DEFAULT 0,

    -- shard binding (set on account-level nodes, inherited by descendants)
    tenant_shard_id UUID REFERENCES tenant_shards(id),

    metadata        JSONB DEFAULT '{}',
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_org_lft ON org_nodes (lft);
CREATE UNIQUE INDEX idx_org_rgt ON org_nodes (rgt);
CREATE INDEX idx_org_parent ON org_nodes (parent_id);
CREATE INDEX idx_org_type ON org_nodes (node_type);
CREATE INDEX idx_org_shard ON org_nodes (tenant_shard_id) WHERE tenant_shard_id IS NOT NULL;
```

### tenant_shards

```sql
CREATE TABLE tenant_shards (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,      -- "shard-acme"
    database_url    TEXT NOT NULL,             -- full connection string
    database_name   TEXT NOT NULL,
    host            TEXT NOT NULL,
    port            INTEGER NOT NULL DEFAULT 5432,
    pool_size       INTEGER NOT NULL DEFAULT 10,
    status          TEXT NOT NULL DEFAULT 'active',
    retention_days  INTEGER NOT NULL DEFAULT 90,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### users

```sql
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email           TEXT NOT NULL UNIQUE,
    name            TEXT NOT NULL,
    password_hash   TEXT NOT NULL,
    is_superadmin   BOOLEAN NOT NULL DEFAULT false,
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### user_grants

Users get access at specific org node levels. Access cascades to all
descendants via nested set.

```sql
CREATE TABLE user_grants (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    org_node_id     UUID NOT NULL REFERENCES org_nodes(id) ON DELETE CASCADE,
    role            TEXT NOT NULL,            -- admin, analyst, viewer
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (user_id, org_node_id)
);

CREATE INDEX idx_grants_user ON user_grants (user_id);
CREATE INDEX idx_grants_node ON user_grants (org_node_id);
```

### enrollment_tokens

```sql
CREATE TABLE enrollment_tokens (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_node_id     UUID NOT NULL REFERENCES org_nodes(id),
    token           TEXT NOT NULL UNIQUE,
    label           TEXT,
    uses_remaining  INTEGER,                  -- null = unlimited
    expires_at      TIMESTAMPTZ,
    created_by      UUID REFERENCES users(id),
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_tokens_node ON enrollment_tokens (org_node_id);
```

### policy_templates

Global policy templates that can be pushed to tenants.

```sql
CREATE TABLE policy_templates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL UNIQUE,
    policy_type     TEXT NOT NULL,            -- dlp, response, detection, device, config
    content         TEXT NOT NULL,            -- TOML body
    version         INTEGER NOT NULL DEFAULT 1,
    created_by      UUID REFERENCES users(id),
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
```

### alert_integrations

Webhook/notification targets, scoped to org nodes.

```sql
CREATE TABLE alert_integrations (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_node_id     UUID NOT NULL REFERENCES org_nodes(id),
    integration_type TEXT NOT NULL,           -- slack, pagerduty, email, webhook
    name            TEXT NOT NULL,
    config          JSONB NOT NULL,           -- { url, channel, api_key, etc. }
    enabled         BOOLEAN NOT NULL DEFAULT true,
    severity_filter TEXT[] DEFAULT '{suspicious,malicious}',
    inserted_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_alerts_node ON alert_integrations (org_node_id);
```

### audit_log (global)

```sql
CREATE TABLE audit_log (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id         UUID REFERENCES users(id),
    org_node_id     UUID REFERENCES org_nodes(id),
    action          TEXT NOT NULL,
    target_type     TEXT,
    target_id       UUID,
    detail          JSONB,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user ON audit_log (user_id, timestamp DESC);
CREATE INDEX idx_audit_node ON audit_log (org_node_id, timestamp DESC);
```

---

## Tenant DB Schema

Each tenant database contains the same schema. Migrations run against
all tenant DBs in parallel when the console is upgraded.

### agents

```sql
CREATE TABLE agents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_node_id     UUID NOT NULL,           -- cross-ref to meta.org_nodes
    hostname        TEXT NOT NULL,
    os              TEXT NOT NULL,
    os_version      TEXT,
    arch            TEXT,
    agent_version   TEXT NOT NULL,
    ip_address      INET,
    mac_address     MACADDR,
    status          TEXT NOT NULL DEFAULT 'unknown',
    last_heartbeat  TIMESTAMPTZ,
    enrolled_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    config_version  INTEGER NOT NULL DEFAULT 0,
    tags            TEXT[] DEFAULT '{}',
    metadata        JSONB DEFAULT '{}',

    events_processed    BIGINT DEFAULT 0,
    threats_detected    BIGINT DEFAULT 0,
    dlp_blocks          BIGINT DEFAULT 0,
    sensor_healthy      BOOLEAN DEFAULT true,
    pipeline_latency_us BIGINT DEFAULT 0,
    store_size_bytes    BIGINT DEFAULT 0,
    uptime_secs         BIGINT DEFAULT 0
);

CREATE INDEX idx_agents_node ON agents (org_node_id);
CREATE INDEX idx_agents_status ON agents (status);
CREATE INDEX idx_agents_heartbeat ON agents (last_heartbeat);
CREATE INDEX idx_agents_tags ON agents USING GIN (tags);
```

### events (partitioned by month)

```sql
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
    ppid            INTEGER,
    process_name    TEXT,
    process_path    TEXT,
    cmdline         TEXT,
    username        TEXT,

    payload         JSONB NOT NULL,

    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

-- Partition template (created by Oban worker):
-- CREATE TABLE events_2026_03 PARTITION OF events
--     FOR VALUES FROM ('2026-03-01') TO ('2026-04-01');

CREATE INDEX idx_events_agent ON events (agent_id, timestamp DESC);
CREATE INDEX idx_events_node ON events (org_node_id, timestamp DESC);
CREATE INDEX idx_events_storyline ON events (storyline_id, timestamp);
CREATE INDEX idx_events_type ON events (event_type, timestamp DESC);
CREATE INDEX idx_events_severity ON events (severity, timestamp DESC)
    WHERE severity NOT IN ('info');
CREATE INDEX idx_events_process ON events (process_name, timestamp DESC)
    WHERE process_name IS NOT NULL;
```

### threats (partitioned by month)

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
    assigned_to_email TEXT,                   -- from meta.users, denormalized
    resolved_at     TIMESTAMPTZ,
    resolution_note TEXT,
    timestamp       TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    verdicts        JSONB NOT NULL,
    process_name    TEXT,
    process_path    TEXT,
    summary         TEXT,

    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE INDEX idx_threats_agent ON threats (agent_id, timestamp DESC);
CREATE INDEX idx_threats_node ON threats (org_node_id, timestamp DESC);
CREATE INDEX idx_threats_status ON threats (status, threat_level, timestamp DESC);
CREATE INDEX idx_threats_storyline ON threats (storyline_id);
```

### storylines

```sql
CREATE TABLE storylines (
    id              UUID PRIMARY KEY,
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    root_pid        INTEGER,
    root_process    TEXT,
    root_path       TEXT,
    status          TEXT NOT NULL DEFAULT 'active',
    max_severity    TEXT NOT NULL DEFAULT 'info',
    threat_count    INTEGER NOT NULL DEFAULT 0,
    event_count     INTEGER NOT NULL DEFAULT 0,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    process_tree    JSONB
);

CREATE INDEX idx_storylines_agent ON storylines (agent_id, last_seen DESC);
CREATE INDEX idx_storylines_node ON storylines (org_node_id, last_seen DESC);
CREATE INDEX idx_storylines_severity ON storylines (max_severity, last_seen DESC)
    WHERE max_severity NOT IN ('info');
```

### dlp_events (partitioned by month)

```sql
CREATE TABLE dlp_events (
    id              UUID NOT NULL,
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    received_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    action          TEXT NOT NULL,
    pid             INTEGER NOT NULL,
    process_name    TEXT NOT NULL,
    file_path       TEXT NOT NULL,
    file_type       TEXT NOT NULL,
    domain          TEXT NOT NULL,
    domain_category TEXT,
    username        TEXT,

    PRIMARY KEY (id, timestamp)
) PARTITION BY RANGE (timestamp);

CREATE INDEX idx_dlp_agent ON dlp_events (agent_id, timestamp DESC);
CREATE INDEX idx_dlp_node ON dlp_events (org_node_id, timestamp DESC);
CREATE INDEX idx_dlp_action ON dlp_events (action, timestamp DESC);
CREATE INDEX idx_dlp_domain ON dlp_events (domain, timestamp DESC);
```

### response_actions

```sql
CREATE TABLE response_actions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    threat_id       UUID,
    action_type     TEXT NOT NULL,
    target          TEXT NOT NULL,
    initiated_by    TEXT NOT NULL,
    success         BOOLEAN NOT NULL,
    detail          TEXT,
    timestamp       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_response_agent ON response_actions (agent_id, timestamp DESC);
```

### vulnerabilities

```sql
CREATE TABLE vulnerabilities (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    cve_id          TEXT NOT NULL,
    package_name    TEXT NOT NULL,
    package_version TEXT NOT NULL,
    package_source  TEXT,
    cvss_score      REAL,
    severity        TEXT NOT NULL,
    fixed_version   TEXT,
    scan_timestamp  TIMESTAMPTZ NOT NULL,
    status          TEXT NOT NULL DEFAULT 'open',

    UNIQUE (agent_id, cve_id, package_name)
);

CREATE INDEX idx_vuln_agent ON vulnerabilities (agent_id);
CREATE INDEX idx_vuln_node ON vulnerabilities (org_node_id);
CREATE INDEX idx_vuln_severity ON vulnerabilities (severity, cvss_score DESC);
```

### device_events

```sql
CREATE TABLE device_events (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    timestamp       TIMESTAMPTZ NOT NULL,
    device_type     TEXT NOT NULL,
    action          TEXT NOT NULL,
    vendor_id       INTEGER,
    product_id      INTEGER,
    serial_number   TEXT,
    device_class    TEXT,
    manufacturer    TEXT,
    product_name    TEXT,
    policy_decision TEXT NOT NULL
);

CREATE INDEX idx_device_agent ON device_events (agent_id, timestamp DESC);
CREATE INDEX idx_device_node ON device_events (org_node_id, timestamp DESC);
```

### network_hosts

```sql
CREATE TABLE network_hosts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL,
    org_node_id     UUID NOT NULL,
    ip_address      INET NOT NULL,
    mac_address     MACADDR,
    hostname        TEXT,
    vendor          TEXT,
    first_seen      TIMESTAMPTZ NOT NULL,
    last_seen       TIMESTAMPTZ NOT NULL,
    is_internal     BOOLEAN NOT NULL DEFAULT true,
    open_ports      INTEGER[] DEFAULT '{}',

    UNIQUE (agent_id, ip_address)
);

CREATE INDEX idx_nethost_agent ON network_hosts (agent_id);
CREATE INDEX idx_nethost_node ON network_hosts (org_node_id);
```

### applied_policies

Tracks which policies are deployed to which agents in this tenant.

```sql
CREATE TABLE applied_policies (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_id        UUID NOT NULL,
    policy_type     TEXT NOT NULL,
    policy_name     TEXT NOT NULL,
    content_hash    TEXT NOT NULL,             -- SHA-256 of content
    version         INTEGER NOT NULL,
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    status          TEXT NOT NULL DEFAULT 'pending',

    UNIQUE (agent_id, policy_type)
);
```

---

## Ecto Schema Mapping

### Meta DB (Murtaugh.Repo)

| Table | Schema | Context |
|---|---|---|
| org_nodes | `Murtaugh.Org.Node` | `Murtaugh.Org` |
| tenant_shards | `Murtaugh.Org.Shard` | `Murtaugh.Org` |
| users | `Murtaugh.Accounts.User` | `Murtaugh.Accounts` |
| user_grants | `Murtaugh.Accounts.Grant` | `Murtaugh.Accounts` |
| enrollment_tokens | `Murtaugh.Fleet.EnrollmentToken` | `Murtaugh.Fleet` |
| policy_templates | `Murtaugh.Policy.Template` | `Murtaugh.Policy` |
| alert_integrations | `Murtaugh.Alerts.Integration` | `Murtaugh.Alerts` |
| audit_log | `Murtaugh.Audit.Entry` | `Murtaugh.Audit` |

### Tenant DB (Murtaugh.TenantRepo — dynamic)

| Table | Schema | Context |
|---|---|---|
| agents | `Murtaugh.Fleet.Agent` | `Murtaugh.Fleet` |
| events | `Murtaugh.Telemetry.Event` | `Murtaugh.Telemetry` |
| threats | `Murtaugh.Detection.Threat` | `Murtaugh.Detection` |
| storylines | `Murtaugh.Detection.Storyline` | `Murtaugh.Detection` |
| dlp_events | `Murtaugh.Dlp.Event` | `Murtaugh.Dlp` |
| response_actions | `Murtaugh.Response.Action` | `Murtaugh.Response` |
| vulnerabilities | `Murtaugh.Vuln.Finding` | `Murtaugh.Vuln` |
| device_events | `Murtaugh.DeviceControl.Event` | `Murtaugh.DeviceControl` |
| network_hosts | `Murtaugh.Discovery.Host` | `Murtaugh.Discovery` |
| applied_policies | `Murtaugh.Policy.Applied` | `Murtaugh.Policy` |

### Cross-DB References

Tenant DB tables reference `org_node_id` (UUID) which lives in the meta DB.
This is an intentional denormalization — no foreign key constraint across
databases. The org_node_id is set at write time and never changes. If an
org node is deleted, a cleanup job removes orphaned records from the
tenant DB.
