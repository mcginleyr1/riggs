PROTO_DIR   := proto
PROTO_FILES := $(shell find $(PROTO_DIR) -name '*.proto')

# Output directories
ELIXIR_OUT  := lib/riggs/proto
RUST_OUT    := ../riggs-agent/src/proto

# protoc plugins
GRPC_ELIXIR_PLUGIN := $(shell which grpc_elixir_plugin 2>/dev/null || echo protoc-gen-elixir)

.PHONY: proto proto-elixir proto-rust clean-proto

proto: proto-elixir proto-rust

proto-elixir:
	@echo "==> Generating Elixir protobuf modules..."
	@mkdir -p $(ELIXIR_OUT)
	protoc \
		--proto_path=$(PROTO_DIR) \
		--elixir_out=plugins=grpc:$(ELIXIR_OUT) \
		$(PROTO_FILES)
	@echo "==> Elixir proto files generated in $(ELIXIR_OUT)"

proto-rust:
	@echo "==> Generating Rust protobuf modules via tonic-build..."
	@echo "    (Run 'cargo build' in the agent crate — tonic-build compiles protos at build time via build.rs)"
	@echo "    Proto files are at: $(PROTO_DIR)/riggs/v1/*.proto"
	@echo ""
	@echo "    Example build.rs:"
	@echo "      tonic_build::configure()"
	@echo "          .build_server(false)"
	@echo "          .compile(&["
	@echo "              \"proto/riggs/v1/common.proto\","
	@echo "              \"proto/riggs/v1/agent_service.proto\","
	@echo "              \"proto/riggs/v1/command_service.proto\","
	@echo "          ], &[\"proto\"])"
	@echo "          .unwrap();"

clean-proto:
	@echo "==> Cleaning generated proto files..."
	rm -rf $(ELIXIR_OUT)/*.pb.ex
