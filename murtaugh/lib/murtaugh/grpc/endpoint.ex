defmodule Murtaugh.Grpc.Endpoint do
  @moduledoc false
  use GRPC.Endpoint

  intercept GRPC.Server.Interceptors.Logger
  intercept Murtaugh.Grpc.Interceptors.AgentAuth
  run Murtaugh.Grpc.AgentServiceImpl
end
