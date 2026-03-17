defmodule Murtaugh.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      MurtaughWeb.Telemetry,
      Murtaugh.Repo,
      {DNSCluster, query: Application.get_env(:murtaugh, :dns_cluster_query) || :ignore},
      {Phoenix.PubSub, name: Murtaugh.PubSub},
      Murtaugh.ShardManager,
      Murtaugh.Ingest.AgentRegistry,
      {GRPC.Server.Supervisor, endpoint: Murtaugh.Grpc.Endpoint, port: 4001},
      # Start to serve requests, typically the last entry
      MurtaughWeb.Endpoint
    ]

    # See https://hexdocs.pm/elixir/Supervisor.html
    # for other strategies and supported options
    opts = [strategy: :one_for_one, name: Murtaugh.Supervisor]
    Supervisor.start_link(children, opts)
  end

  # Tell Phoenix to update the endpoint configuration
  # whenever the application is updated.
  @impl true
  def config_change(changed, _new, removed) do
    MurtaughWeb.Endpoint.config_change(changed, removed)
    :ok
  end
end
