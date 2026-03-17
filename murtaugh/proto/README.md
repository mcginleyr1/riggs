# Riggs gRPC Protocol Definitions

Protocol buffer definitions for the Riggs endpoint protection system.
Used by both the Rust agent (tonic/prost) and the Elixir console (grpc + protobuf).

## File Structure

```
proto/riggs/v1/
  common.proto           Shared types: ProcessContext
  agent_service.proto    Agent -> Console RPCs and messages
  command_service.proto  Console -> Agent RPCs and messages
```

- **common.proto** defines `ProcessContext`, used by both services.
- **agent_service.proto** defines the `AgentService` with 9 RPCs covering
  enrollment, heartbeat, event streaming, threat reporting, DLP, vulnerability
  scanning, device control, network discovery, and storylines.
- **command_service.proto** defines the `CommandService` with a bidirectional
  `CommandStream` RPC. The `AgentCommand` message uses a `oneof` to dispatch
  10 command types (kill, suspend, quarantine, network contain/release, policy
  update, config update, scan trigger, feed refresh, remote shell).

## Prerequisites

Install `protoc` (the Protocol Buffer compiler):

```sh
# macOS
brew install protobuf

# Ubuntu/Debian
sudo apt install -y protobuf-compiler

# From source
# https://github.com/protocolbuffers/protobuf/releases
```

## Generating Elixir Code

The Elixir side uses the `protobuf` and `grpc` hex packages. Add them to
`mix.exs`:

```elixir
{:grpc, "~> 0.9"},
{:protobuf, "~> 0.13"},
```

Install the protoc plugin for Elixir:

```sh
mix escript.install hex protobuf
```

Then generate:

```sh
make proto-elixir
```

This runs `protoc --elixir_out=plugins=grpc:lib/riggs/proto` and places
generated `.pb.ex` files under `lib/riggs/proto/`.

## Generating Rust Code

The Rust agent uses `tonic-build` to compile protos at build time.
Add to the agent crate's `Cargo.toml`:

```toml
[dependencies]
tonic = "0.12"
prost = "0.13"

[build-dependencies]
tonic-build = "0.12"
```

Create a `build.rs` in the agent crate:

```rust
fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(false)
        .compile(
            &[
                "proto/riggs/v1/common.proto",
                "proto/riggs/v1/agent_service.proto",
                "proto/riggs/v1/command_service.proto",
            ],
            &["proto"],
        )?;
    Ok(())
}
```

Then `cargo build` compiles the protos automatically. Generated code ends
up in `OUT_DIR` and is included via `tonic::include_proto!("riggs.v1")`.

Running `make proto-rust` prints a reminder of this setup (tonic-build does
not use `protoc` directly for Rust code generation).
