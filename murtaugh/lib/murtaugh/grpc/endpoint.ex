defmodule Murtaugh.Grpc.Endpoint do
  @moduledoc false
  use GRPC.Endpoint

  intercept GRPC.Server.Interceptors.Logger
  run Murtaugh.Grpc.AgentServiceImpl
end
