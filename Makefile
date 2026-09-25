.PHONY: build install uninstall check fmt clippy test clean

build:
	cargo build --release

install:
	sudo ./install/install.sh

uninstall:
	sudo ./install/uninstall.sh

check:
	cargo check --workspace

fmt:
	cargo fmt --all --check

clippy:
	cargo clippy --workspace --all-targets -- -D warnings

test:
	cargo test --workspace

clean:
	cargo clean
