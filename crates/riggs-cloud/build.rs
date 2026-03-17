fn main() {
    tonic_build::configure()
        .build_client(true)
        .build_server(false)
        .compile_protos(
            &[
                "../../murtaugh/proto/riggs/v1/common.proto",
                "../../murtaugh/proto/riggs/v1/agent_service.proto",
                "../../murtaugh/proto/riggs/v1/command_service.proto",
            ],
            &["../../murtaugh/proto"],
        )
        .expect("failed to compile riggs.v1 protos");
}
