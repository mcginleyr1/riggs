import Config

# config/runtime.exs is executed for all environments, including
# during releases. It is executed after compilation and before the
# system starts, so it is typically used to load production configuration
# and secrets from environment variables or elsewhere. Do not define
# any compile-time configuration in here, as it won't be applied.
# The block below contains prod specific runtime configuration.

# ## Using releases
#
# If you use `mix release`, you need to explicitly enable the server
# by passing the PHX_SERVER=true when you start it:
#
#     PHX_SERVER=true bin/murtaugh start
#
# Alternatively, you can use `mix phx.gen.release` to generate a `bin/server`
# script that automatically sets the env var above.
if System.get_env("PHX_SERVER") do
  config :murtaugh, MurtaughWeb.Endpoint, server: true
end

bind_ip =
  case System.get_env("PHX_BIND", "127.0.0.1") do
    "0.0.0.0" -> {0, 0, 0, 0}
    "127.0.0.1" -> {127, 0, 0, 1}
    other -> other |> String.split(".") |> Enum.map(&String.to_integer/1) |> List.to_tuple()
  end

config :murtaugh, MurtaughWeb.Endpoint,
  http: [ip: bind_ip, port: String.to_integer(System.get_env("PORT", "4000"))]

# Archive storage — env vars override config.exs defaults
if storage = System.get_env("ARCHIVE_STORAGE") do
  config :murtaugh, Murtaugh.Archive,
    storage: storage,
    bucket: System.get_env("ARCHIVE_BUCKET", "murtaugh-archive"),
    s3_endpoint: System.get_env("ARCHIVE_S3_ENDPOINT"),
    s3_region: System.get_env("ARCHIVE_S3_REGION", "us-east-1"),
    s3_access_key: System.get_env("ARCHIVE_S3_ACCESS_KEY"),
    s3_secret_key: System.get_env("ARCHIVE_S3_SECRET_KEY"),
    local_path: System.get_env("ARCHIVE_LOCAL_PATH", "/tmp/murtaugh-archive")
end

# Database URL override (for docker-compose and prod)
if database_url = System.get_env("DATABASE_URL") do
  config :murtaugh, Murtaugh.Repo,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE", "10"))
end

# gRPC agent-ingest server. mTLS (bring-your-own-PKI) is enabled only when all
# three PEM paths are supplied; otherwise application.ex starts it in cleartext
# and logs a warning. cacertfile is the CA that signed agent client certs.
grpc_tls =
  case {System.get_env("MURTAUGH_GRPC_CERT"), System.get_env("MURTAUGH_GRPC_KEY"),
        System.get_env("MURTAUGH_GRPC_CACERT")} do
    {cert, key, cacert} when is_binary(cert) and is_binary(key) and is_binary(cacert) ->
      [certfile: cert, keyfile: key, cacertfile: cacert]

    _ ->
      nil
  end

# TLS mode: "disabled" (plaintext), "optional" (mTLS when certs are present,
# else plaintext with a warning), or "required" (fail to start without certs).
config :murtaugh, :grpc,
  port: String.to_integer(System.get_env("MURTAUGH_GRPC_PORT") || "4001"),
  tls_mode: System.get_env("MURTAUGH_GRPC_TLS_MODE", "optional"),
  tls: grpc_tls

if config_env() == :prod do
  database_url =
    System.get_env("DATABASE_URL") ||
      raise """
      environment variable DATABASE_URL is missing.
      For example: ecto://USER:PASS@HOST/DATABASE
      """

  maybe_ipv6 = if System.get_env("ECTO_IPV6") in ~w(true 1), do: [:inet6], else: []

  config :murtaugh, Murtaugh.Repo,
    # ssl: true,
    url: database_url,
    pool_size: String.to_integer(System.get_env("POOL_SIZE") || "10"),
    # For machines with several cores, consider starting multiple pools of `pool_size`
    # pool_count: 4,
    socket_options: maybe_ipv6

  # The secret key base is used to sign/encrypt cookies and other secrets.
  # A default value is used in config/dev.exs and config/test.exs but you
  # want to use a different value for prod and you most likely don't want
  # to check this value into version control, so we use an environment
  # variable instead.
  secret_key_base =
    System.get_env("SECRET_KEY_BASE") ||
      raise """
      environment variable SECRET_KEY_BASE is missing.
      You can generate one by calling: mix phx.gen.secret
      """

  host = System.get_env("PHX_HOST") || "example.com"

  config :murtaugh, :dns_cluster_query, System.get_env("DNS_CLUSTER_QUERY")

  config :murtaugh, MurtaughWeb.Endpoint,
    url: [host: host, port: 443, scheme: "https"],
    http: [
      # Enable IPv6 and bind on all interfaces.
      # Set it to  {0, 0, 0, 0, 0, 0, 0, 1} for local network only access.
      # See the documentation on https://hexdocs.pm/bandit/Bandit.html#t:options/0
      # for details about using IPv6 vs IPv4 and loopback vs public addresses.
      ip: {0, 0, 0, 0, 0, 0, 0, 0}
    ],
    secret_key_base: secret_key_base

  # ## SSL Support
  #
  # To get SSL working, you will need to add the `https` key
  # to your endpoint configuration:
  #
  #     config :murtaugh, MurtaughWeb.Endpoint,
  #       https: [
  #         ...,
  #         port: 443,
  #         cipher_suite: :strong,
  #         keyfile: System.get_env("SOME_APP_SSL_KEY_PATH"),
  #         certfile: System.get_env("SOME_APP_SSL_CERT_PATH")
  #       ]
  #
  # The `cipher_suite` is set to `:strong` to support only the
  # latest and more secure SSL ciphers. This means old browsers
  # and clients may not be supported. You can set it to
  # `:compatible` for wider support.
  #
  # `:keyfile` and `:certfile` expect an absolute path to the key
  # and cert in disk or a relative path inside priv, for example
  # "priv/ssl/server.key". For all supported SSL configuration
  # options, see https://hexdocs.pm/plug/Plug.SSL.html#configure/1
  #
  # We also recommend setting `force_ssl` in your config/prod.exs,
  # ensuring no data is ever sent via http, always redirecting to https:
  #
  #     config :murtaugh, MurtaughWeb.Endpoint,
  #       force_ssl: [hsts: true]
  #
  # Check `Plug.SSL` for all available options in `force_ssl`.

  # ## Configuring the mailer
  #
  # In production you need to configure the mailer to use a different adapter.
  # Here is an example configuration for Mailgun:
  #
  #     config :murtaugh, Murtaugh.Mailer,
  #       adapter: Swoosh.Adapters.Mailgun,
  #       api_key: System.get_env("MAILGUN_API_KEY"),
  #       domain: System.get_env("MAILGUN_DOMAIN")
  #
  # Most non-SMTP adapters require an API client. Swoosh supports Req, Hackney,
  # and Finch out-of-the-box. This configuration is typically done at
  # compile-time in your config/prod.exs:
  #
  #     config :swoosh, :api_client, Swoosh.ApiClient.Req
  #
  # See https://hexdocs.pm/swoosh/Swoosh.html#module-installation for details.
end
