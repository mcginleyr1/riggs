## Enrollment

defmodule Riggs.V1.EnrollRequest do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :hostname, 1, type: :string
  field :os, 2, type: :string
  field :os_version, 3, type: :string
  field :arch, 4, type: :string
  field :agent_version, 5, type: :string
  field :ip_address, 6, type: :string
  field :mac_address, 7, type: :string
  field :enrollment_token, 8, type: :string
end

defmodule Riggs.V1.EnrollResponse do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :client_cert, 2, type: :bytes
  field :client_key, 3, type: :bytes
  field :ca_cert, 4, type: :bytes
  field :heartbeat_interval_secs, 5, type: :int32
  field :event_batch_size, 6, type: :int32
  field :event_flush_interval_ms, 7, type: :int32
end

## Heartbeat

defmodule Riggs.V1.AgentHealth do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :events_processed, 1, type: :uint64
  field :threats_detected, 2, type: :uint64
  field :dlp_blocks, 3, type: :uint64
  field :sensor_healthy, 4, type: :bool
  field :pipeline_latency_us, 5, type: :uint64
  field :store_size_bytes, 6, type: :uint64
  field :uptime_secs, 7, type: :uint64
  field :agent_version, 8, type: :string
  field :config_version, 9, type: :int32
end

defmodule Riggs.V1.HeartbeatRequest do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :timestamp, 2, type: Google.Protobuf.Timestamp
  field :health, 3, type: Riggs.V1.AgentHealth
end

defmodule Riggs.V1.HeartbeatResponse do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :accepted, 1, type: :bool
  field :commands, 2, repeated: true, type: Riggs.V1.AgentCommand
end

## Events

defmodule Riggs.V1.Event do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :event_id, 1, type: :string
  field :storyline_id, 2, type: :string
  field :event_type, 3, type: :string
  field :severity, 4, type: :string
  field :timestamp, 5, type: Google.Protobuf.Timestamp
  field :process_context, 6, type: Riggs.V1.ProcessContext
  field :payload_json, 7, type: :bytes
end

defmodule Riggs.V1.EventBatch do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :events, 2, repeated: true, type: Riggs.V1.Event
  field :batch_seq, 3, type: :int32
end

defmodule Riggs.V1.EventAck do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :batch_seq, 1, type: :int32
  field :accepted, 2, type: :bool
end

## Threats

defmodule Riggs.V1.VerdictDetail do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :source, 1, type: :string
  field :threat_level, 2, type: :string
  field :confidence, 3, type: :float
  field :description, 4, type: :string
end

defmodule Riggs.V1.ThreatReport do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :event_id, 2, type: :string
  field :storyline_id, 3, type: :string
  field :threat_level, 4, type: :string
  field :final_score, 5, type: :float
  field :timestamp, 6, type: Google.Protobuf.Timestamp
  field :verdicts, 7, repeated: true, type: Riggs.V1.VerdictDetail
  field :process_name, 8, type: :string
  field :process_path, 9, type: :string
  field :summary, 10, type: :string
end

defmodule Riggs.V1.ThreatAck do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :accepted, 1, type: :bool
  field :threat_id, 2, type: :string
end

## DLP

defmodule Riggs.V1.DlpEventReport do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :timestamp, 2, type: Google.Protobuf.Timestamp
  field :action, 3, type: :string
  field :pid, 4, type: :uint32
  field :process_name, 5, type: :string
  field :file_path, 6, type: :string
  field :file_type, 7, type: :string
  field :domain, 8, type: :string
  field :domain_category, 9, type: :string
  field :username, 10, type: :string
end

defmodule Riggs.V1.DlpEventAck do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :accepted, 1, type: :bool
end

## Vulnerability

defmodule Riggs.V1.VulnFinding do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :cve_id, 1, type: :string
  field :package_name, 2, type: :string
  field :package_version, 3, type: :string
  field :package_source, 4, type: :string
  field :cvss_score, 5, type: :float
  field :severity, 6, type: :string
  field :fixed_version, 7, type: :string
end

defmodule Riggs.V1.VulnScanReport do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :scan_timestamp, 2, type: Google.Protobuf.Timestamp
  field :findings, 3, repeated: true, type: Riggs.V1.VulnFinding
end

defmodule Riggs.V1.VulnScanAck do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :accepted, 1, type: :bool
  field :findings_stored, 2, type: :int32
end

## Device Control

defmodule Riggs.V1.DeviceEventReport do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :timestamp, 2, type: Google.Protobuf.Timestamp
  field :device_type, 3, type: :string
  field :action, 4, type: :string
  field :vendor_id, 5, type: :uint32
  field :product_id, 6, type: :uint32
  field :serial_number, 7, type: :string
  field :device_class, 8, type: :string
  field :manufacturer, 9, type: :string
  field :product_name, 10, type: :string
  field :policy_decision, 11, type: :string
end

defmodule Riggs.V1.DeviceEventAck do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :accepted, 1, type: :bool
end

## Network Discovery

defmodule Riggs.V1.DiscoveredHost do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :ip_address, 1, type: :string
  field :mac_address, 2, type: :string
  field :hostname, 3, type: :string
  field :vendor, 4, type: :string
  field :first_seen, 5, type: Google.Protobuf.Timestamp
  field :last_seen, 6, type: Google.Protobuf.Timestamp
  field :open_ports, 7, repeated: true, type: :uint32
end

defmodule Riggs.V1.NetworkMapUpdate do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :hosts, 2, repeated: true, type: Riggs.V1.DiscoveredHost
end

defmodule Riggs.V1.NetworkMapAck do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :accepted, 1, type: :bool
end

## Storylines

defmodule Riggs.V1.StorylineUpdate do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :agent_id, 1, type: :string
  field :storyline_id, 2, type: :string
  field :status, 3, type: :string
  field :max_severity, 4, type: :string
  field :threat_count, 5, type: :int32
  field :event_count, 6, type: :int32
  field :first_seen, 7, type: Google.Protobuf.Timestamp
  field :last_seen, 8, type: Google.Protobuf.Timestamp
  field :root_pid, 9, type: :uint32
  field :root_process, 10, type: :string
  field :root_path, 11, type: :string
  field :process_tree_json, 12, type: :bytes
end

defmodule Riggs.V1.StorylineAck do
  @moduledoc false
  use Protobuf, syntax: :proto3

  field :accepted, 1, type: :bool
end
