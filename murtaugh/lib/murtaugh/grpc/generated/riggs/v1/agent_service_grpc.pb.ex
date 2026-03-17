defmodule Riggs.V1.AgentService.Service do
  @moduledoc false
  use GRPC.Service, name: "riggs.v1.AgentService", protoc_gen_elixir_version: "0.14.0"

  rpc :Enroll, Riggs.V1.EnrollRequest, Riggs.V1.EnrollResponse
  rpc :Heartbeat, stream(Riggs.V1.HeartbeatRequest), stream(Riggs.V1.HeartbeatResponse)
  rpc :StreamEvents, stream(Riggs.V1.EventBatch), stream(Riggs.V1.EventAck)
  rpc :ReportThreat, Riggs.V1.ThreatReport, Riggs.V1.ThreatAck
  rpc :ReportDlpEvent, Riggs.V1.DlpEventReport, Riggs.V1.DlpEventAck
  rpc :ReportVulnScan, Riggs.V1.VulnScanReport, Riggs.V1.VulnScanAck
  rpc :ReportDeviceEvent, Riggs.V1.DeviceEventReport, Riggs.V1.DeviceEventAck
  rpc :UpdateNetworkMap, Riggs.V1.NetworkMapUpdate, Riggs.V1.NetworkMapAck
  rpc :UpdateStoryline, Riggs.V1.StorylineUpdate, Riggs.V1.StorylineAck
end

defmodule Riggs.V1.AgentService.Stub do
  @moduledoc false
  use GRPC.Stub, service: Riggs.V1.AgentService.Service
end
