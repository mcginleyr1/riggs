defmodule Murtaugh.Grpc.AgentAuth do
  @moduledoc """
  Binds the mTLS client certificate to the agent identity it is allowed to act
  as (C5). The certificate's Common Name is treated as the agent_id the peer may
  submit telemetry for; handlers call `verify!/2` to reject any request whose
  body claims a different agent_id.

  Without this, any holder of a valid agent certificate could impersonate any
  other agent by simply setting a different `agent_id` in the request body.

  Posture:
    * no peer certificate (mTLS disabled for local/dev) -> permissive
    * certificate present, CN matches claimed agent_id   -> allowed
    * certificate present, CN differs                    -> permission_denied
    * certificate present, no CN could be extracted      -> permission_denied
      (a certificate that carries no identity cannot authorize anything)
  """
  require Record
  require Logger

  # commonName == id-at-commonName (OID 2.5.4.3)
  @common_name_oid {2, 5, 4, 3}

  Record.defrecordp(
    :otp_cert,
    :OTPCertificate,
    Record.extract(:OTPCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :otp_tbs_cert,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :attr,
    :AttributeTypeAndValue,
    Record.extract(:AttributeTypeAndValue, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  @typedoc "Authenticated identity stashed on the stream by the interceptor."
  @type identity :: nil | {:ok, String.t()} | :no_identity

  @doc "Derive the authenticated identity from a DER-encoded peer certificate."
  @spec identity_from_cert(binary() | :undefined | nil) :: identity()
  def identity_from_cert(cert) when cert in [:undefined, nil, ""], do: nil

  def identity_from_cert(der) when is_binary(der) do
    case common_name(der) do
      cn when is_binary(cn) and cn != "" -> {:ok, cn}
      _ -> :no_identity
    end
  rescue
    _ -> :no_identity
  catch
    _, _ -> :no_identity
  end

  @doc "Read the identity the interceptor stored on the stream."
  @spec authenticated_id(GRPC.Server.Stream.t() | map()) :: identity()
  def authenticated_id(%{local: %{authenticated_agent_id: id}}), do: id
  def authenticated_id(_), do: nil

  @doc """
  Reject the RPC unless the claimed agent_id is authorized by the client cert.
  Raises `GRPC.RPCError` on mismatch; returns `:ok` otherwise.
  """
  @spec verify!(GRPC.Server.Stream.t() | map(), String.t()) :: :ok
  def verify!(stream, claimed_agent_id) do
    case authenticated_id(stream) do
      nil ->
        :ok

      {:ok, ^claimed_agent_id} ->
        :ok

      {:ok, other} ->
        Logger.warning(
          "gRPC: cert identity #{inspect(other)} attempted to act as agent #{inspect(claimed_agent_id)}"
        )

        raise GRPC.RPCError,
          status: :permission_denied,
          message: "agent_id does not match client certificate"

      :no_identity ->
        raise GRPC.RPCError,
          status: :permission_denied,
          message: "client certificate has no agent identity (CN)"
    end
  end

  defp common_name(der) do
    otp = :public_key.pkix_decode_cert(der, :otp)
    tbs = otp_cert(otp, :tbsCertificate)
    {:rdnSequence, rdns} = otp_tbs_cert(tbs, :subject)

    rdns
    |> List.flatten()
    |> Enum.find_value(fn a ->
      case attr(a, :type) do
        @common_name_oid -> decode_cn_value(attr(a, :value))
        _ -> nil
      end
    end)
  end

  defp decode_cn_value({:utf8String, v}), do: to_string(v)
  defp decode_cn_value({:printableString, v}), do: to_string(v)
  defp decode_cn_value({:teletexString, v}), do: to_string(v)
  defp decode_cn_value(v) when is_list(v), do: to_string(v)
  defp decode_cn_value(v) when is_binary(v), do: v
  defp decode_cn_value(_), do: nil
end
