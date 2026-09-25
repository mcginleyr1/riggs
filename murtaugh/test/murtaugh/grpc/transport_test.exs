defmodule Murtaugh.Grpc.TransportTest do
  # Talks to the real gRPC listener the application starts.
  use ExUnit.Case

  alias Riggs.V1.{AgentService, EnrollRequest}

  setup tags do
    # Handlers run in gRPC server processes, so share the sandbox connection.
    Murtaugh.DataCase.setup_sandbox(tags)
    port = Application.fetch_env!(:murtaugh, :grpc)[:port]
    {:ok, channel} = GRPC.Stub.connect("localhost:#{port}", adapter: GRPC.Client.Adapters.Mint)
    on_exit(fn -> GRPC.Stub.disconnect(channel) end)
    %{channel: channel}
  end

  test "rejects an invalid enrollment token", %{channel: channel} do
    request = %EnrollRequest{hostname: "probe", os: "linux", enrollment_token: "bogus"}

    assert {:error, %GRPC.RPCError{status: 16}} = AgentService.Stub.enroll(channel, request)
  end

  test "bidi StreamEvents processes each batch and replies", %{channel: channel} do
    stream = AgentService.Stub.stream_events(channel)
    batch = %Riggs.V1.EventBatch{agent_id: Ecto.UUID.generate(), batch_seq: 7}
    GRPC.Stub.send_request(stream, batch, end_stream: true)

    assert {:ok, replies} = GRPC.Stub.recv(stream, timeout: 5_000)
    # Unknown agent: the batch is processed and rejected, not silently dropped.
    assert [{:ok, %Riggs.V1.EventAck{batch_seq: 7, accepted: false}}] = Enum.to_list(replies)
  end

  test "rejects request bodies over the size cap", %{channel: channel} do
    request = %EnrollRequest{hostname: String.duplicate("a", 5 * 1024 * 1024)}

    assert {:error, %GRPC.RPCError{status: status}} = AgentService.Stub.enroll(channel, request)
    refute status == 16, "oversized body must be rejected before reaching the handler"
  end
end
