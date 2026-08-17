defmodule Murtaugh.Grpc.Interceptors.AgentAuth do
  @moduledoc """
  Server interceptor that extracts the mTLS client certificate for each RPC and
  stashes the derived agent identity on `stream.local`, so handlers can bind the
  request's claimed `agent_id` to the presenting certificate (C5).

  When no peer certificate is presented (mTLS disabled for local/dev), the
  identity is `nil` and downstream verification stays permissive, matching the
  endpoint's optional-TLS posture.
  """
  @behaviour GRPC.Server.Interceptor

  alias Murtaugh.Grpc.AgentAuth

  @impl true
  def init(opts), do: opts

  @impl true
  def call(req, stream, next, _opts) do
    identity = AgentAuth.identity_from_cert(peer_cert(stream))
    next.(req, %{stream | local: put_identity(stream.local, identity)})
  end

  defp peer_cert(%{adapter: adapter, payload: payload}) when not is_nil(adapter) do
    adapter.get_cert(payload)
  rescue
    _ -> :undefined
  catch
    _, _ -> :undefined
  end

  defp peer_cert(_), do: :undefined

  defp put_identity(local, identity) when is_map(local),
    do: Map.put(local, :authenticated_agent_id, identity)

  defp put_identity(_local, identity), do: %{authenticated_agent_id: identity}
end
