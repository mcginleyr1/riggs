defmodule Murtaugh.Application do
  # See https://hexdocs.pm/elixir/Application.html
  # for more information on OTP Applications
  @moduledoc false

  use Application

  require Logger

  @impl true
  def start(_type, _args) do
    children =
      [
        MurtaughWeb.Telemetry,
        Murtaugh.Repo,
        {DNSCluster, query: Application.get_env(:murtaugh, :dns_cluster_query) || :ignore},
        {Phoenix.PubSub, name: Murtaugh.PubSub},
        Murtaugh.ShardManager.supervisor_child_spec()
      ] ++
        tenant_provisioning() ++
        [
          Murtaugh.Ingest.AgentRegistry,
          grpc_child_spec(),
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

  # Provision/migrate tenant DBs synchronously before the AgentRegistry reads
  # them and agents connect; the start function returns :ignore when done.
  defp tenant_provisioning do
    if Application.get_env(:murtaugh, :provision_tenants_on_boot, true),
      do: [
        %{
          id: :tenant_provisioning,
          start: {Murtaugh.Tenancy, :provision_all_on_boot, []},
          restart: :temporary
        }
      ],
      else: []
  end

  # Build the gRPC ingest server child spec. start_server: true is required for
  # grpc >= 0.10 to actually launch the listener. mTLS (verify_peer +
  # fail_if_no_peer_cert) is enabled when cert paths are configured; otherwise
  # the server runs in cleartext with a loud warning.
  defp grpc_child_spec do
    grpc = Application.get_env(:murtaugh, :grpc, [])
    port = Keyword.get(grpc, :port, 4001)
    mode = Keyword.get(grpc, :tls_mode, "optional")
    ssl = Keyword.get(grpc, :tls)
    opts = [endpoint: Murtaugh.Grpc.Endpoint, port: port, start_server: true]

    case {mode, ssl} do
      {"disabled", _} ->
        {GRPC.Server.Supervisor, opts}

      {_mode, ssl} when is_list(ssl) ->
        ssl = ssl ++ [verify: :verify_peer, fail_if_no_peer_cert: true]
        cred = GRPC.Credential.new(ssl: ssl)
        {GRPC.Server.Supervisor, Keyword.put(opts, :adapter_opts, cred: cred)}

      {"required", _} ->
        raise "MURTAUGH_GRPC_TLS_MODE=required but MURTAUGH_GRPC_CERT/KEY/CACERT are not all set"

      {_optional, _} ->
        Logger.warning(
          "gRPC ingest starting WITHOUT mTLS: agents are unauthenticated and telemetry is cleartext. " <>
            "Set MURTAUGH_GRPC_CERT / MURTAUGH_GRPC_KEY / MURTAUGH_GRPC_CACERT, or " <>
            "MURTAUGH_GRPC_TLS_MODE=disabled to silence this."
        )

        {GRPC.Server.Supervisor, opts}
    end
  end
end
