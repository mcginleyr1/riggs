# Murtaugh — LiveView Pages

## Overview

Every page is a Phoenix LiveView. Real-time updates arrive via PubSub
subscriptions. No polling, no REST endpoints for UI data.

## Page Map

### / — Dashboard

**Route**: `GET /`
**LiveView**: `RiggsWeb.DashboardLive`
**PubSub topics**: `"fleet"`, `"threats"`, `"dlp"`

| Component | Data Source | Live Update |
|---|---|---|
| Fleet health bar (online/offline/degraded) | `Riggs.Fleet.summary()` | `{:agent_status_change, agent}` |
| Threat count by severity (sparkline) | `Riggs.Detection.threat_counts(24h)` | `{:new_threat, threat}` |
| DLP blocks/alerts today | `Riggs.Dlp.daily_counts()` | `{:dlp_event, event}` |
| Events/sec gauge | `Riggs.Telemetry.throughput()` | `{:throughput_update, eps}` |
| Recent threats table (top 10) | `Riggs.Detection.recent_threats(10)` | `{:new_threat, threat}` |
| Recent DLP blocks (top 5) | `Riggs.Dlp.recent_blocks(5)` | `{:dlp_event, event}` |

### /threats — Threat Management

**Route**: `GET /threats`
**LiveView**: `RiggsWeb.ThreatsLive`
**PubSub topics**: `"threats"`

| Component | Notes |
|---|---|
| Filter bar | Severity, status, detection source, agent, time range |
| Threat table | Sortable, paginated, live-updating |
| Bulk actions | Acknowledge, resolve, mark false positive |
| Click-through | Opens threat detail (storyline view) |

### /threats/:id — Threat Detail

**Route**: `GET /threats/:id`
**LiveView**: `RiggsWeb.ThreatDetailLive`
**PubSub topics**: `"agent:#{agent_id}"`

| Component | Notes |
|---|---|
| Verdict breakdown | Each stage's verdict, confidence, description |
| Storyline tree | Process tree visualization (see component below) |
| Event timeline | All events in this storyline, chronological |
| Response actions | Kill, quarantine, contain buttons |
| Triage panel | Assign, change status, add notes |

### /agents — Fleet Overview

**Route**: `GET /agents`
**LiveView**: `RiggsWeb.AgentsLive`
**PubSub topics**: `"fleet"`

| Component | Notes |
|---|---|
| Agent table | Hostname, OS, status, last heartbeat, threats, DLP blocks |
| Status filters | Online, offline, degraded, contained |
| Tag filtering | Filter by user-defined tags |
| Bulk actions | Push policy, contain, release |

### /agents/:id — Agent Detail

**Route**: `GET /agents/:id`
**LiveView**: `RiggsWeb.AgentDetailLive`
**PubSub topics**: `"agent:#{agent_id}"`

| Component | Notes |
|---|---|
| Health panel | Sensor status, pipeline latency, uptime, store size |
| Recent events | Live-updating event stream for this agent |
| Active threats | Threats on this agent |
| DLP activity | Recent blocks/alerts on this agent |
| Installed packages | For vuln context |
| Network map | Discovered hosts around this agent |
| Applied policies | Which policies at which versions |
| Actions | Contain, release, push config, trigger scan, open shell |

### /events — Event Explorer

**Route**: `GET /events`
**LiveView**: `RiggsWeb.EventsLive`
**PubSub topics**: none (query-driven, too high volume for live push)

| Component | Notes |
|---|---|
| Search bar | Full-text across process name, path, domain, cmdline |
| Filters | Event type, severity, agent, time range, storyline ID |
| Results table | Paginated, sortable |
| Event detail panel | Slide-out with full payload JSON |
| Storyline link | Click storyline ID to see full chain |

### /dlp — DLP Dashboard

**Route**: `GET /dlp`
**LiveView**: `RiggsWeb.DlpLive`
**PubSub topics**: `"dlp"`

| Component | Notes |
|---|---|
| Blocks/alerts over time | Chart, 24h/7d/30d toggle |
| Top blocked domains | Bar chart |
| Top blocked file types | Bar chart |
| Top triggering processes | Which apps try to upload most |
| Recent events table | Live-updating |
| Click-through to agent | See agent detail for context |

### /dlp/policies — DLP Policy Management

**Route**: `GET /dlp/policies`
**LiveView**: `RiggsWeb.DlpPoliciesLive`

| Component | Notes |
|---|---|
| Policy list | Name, type, version, agent count |
| Policy editor | TOML editor with syntax highlighting |
| Create new policy | From template or blank |
| Push to agents | Select agents/tags, push with version bump |
| Policy diff | Compare versions |

### /rules — Detection Rules

**Route**: `GET /rules`
**LiveView**: `RiggsWeb.RulesLive`

| Component | Notes |
|---|---|
| Rule list | YARA rules, custom TOML rules, IOC lists |
| Rule editor | Syntax-highlighted editor per rule type |
| Hit stats | Which rules fire most, per-agent breakdown |
| Push to agents | Deploy rule updates |
| IOC manager | Add/remove hashes, domains, IPs |

### /vuln — Vulnerability Dashboard

**Route**: `GET /vuln`
**LiveView**: `RiggsWeb.VulnLive`

| Component | Notes |
|---|---|
| CVE summary | Count by severity across fleet |
| Top vulns | Most common CVEs across agents |
| Agent breakdown | Which agents have which vulns |
| CVE detail | Click to see affected agents, fixed version |

### /devices — Device Control

**Route**: `GET /devices`
**LiveView**: `RiggsWeb.DevicesLive`
**PubSub topics**: `"devices"`

| Component | Notes |
|---|---|
| Recent events | Live-updating connection/block log |
| Device policy editor | USB/Bluetooth modes, allowlists |
| Push policy | Deploy to agents |

### /network — Network Discovery

**Route**: `GET /network`
**LiveView**: `RiggsWeb.NetworkLive`

| Component | Notes |
|---|---|
| Agent selector | Pick which agent's network map to view |
| Host table | IP, MAC, hostname, vendor, first/last seen, ports |
| Network graph | Visual map of discovered hosts (if we want to get fancy) |

### /audit — Audit Log

**Route**: `GET /audit`
**LiveView**: `RiggsWeb.AuditLive`

| Component | Notes |
|---|---|
| Audit table | User, action, target, timestamp |
| Filters | User, action type, time range |
| Detail panel | Full JSONB detail for each entry |

### /settings — Console Settings

**Route**: `GET /settings`
**LiveView**: `RiggsWeb.SettingsLive`

| Component | Notes |
|---|---|
| User management | CRUD users, assign roles |
| Enrollment tokens | Generate/revoke tokens for new agents |
| Alert integrations | Webhook URLs for Slack, PagerDuty, email |
| Retention settings | Event retention period |
| mTLS CA management | View/rotate CA certificate |

## Shared LiveView Components

### StorylineTreeComponent

Renders a process tree visualization for a storyline. Used on threat detail
and agent detail pages.

```elixir
<.storyline_tree storyline={@storyline} events={@storyline_events} />
```

Renders as a vertical tree with:
- Process nodes (PID, name, path)
- Event markers on edges (file create, network connect, etc.)
- Color coding by severity
- Click to expand event details

### ThreatBadge

```elixir
<.threat_badge level={:malicious} />  # red badge
<.threat_badge level={:suspicious} /> # yellow badge
```

### AgentStatusIndicator

```elixir
<.agent_status status={:online} last_heartbeat={~U[2026-03-17 10:00:00Z]} />
```

Green dot + "2m ago" / red dot + "offline since..."

### PolicyEditor

TOML editor component with syntax highlighting (via a JS hook wrapping
CodeMirror or Monaco).

```elixir
<.policy_editor content={@policy.content} on_save="save_policy" />
```

## PubSub Topic Map

| Topic | Events | Subscribers |
|---|---|---|
| `"fleet"` | `{:agent_online, agent}`, `{:agent_offline, agent}`, `{:agent_status_change, agent}` | Dashboard, Agents |
| `"threats"` | `{:new_threat, threat}`, `{:threat_updated, threat}` | Dashboard, Threats |
| `"dlp"` | `{:dlp_event, event}` | Dashboard, DLP |
| `"devices"` | `{:device_event, event}` | Devices |
| `"agent:#{id}"` | `{:heartbeat, health}`, `{:event, event}`, `{:command_ack, ack}` | Agent Detail |
| `"throughput"` | `{:throughput_update, eps}` | Dashboard |
