.PHONY: build install uninstall check clippy test clean

build:
	cargo build --release

install:
	sudo ./install/install.sh

uninstall:
	sudo ./install/uninstall.sh

check:
	cargo check --workspace

clippy:
	cargo clippy --workspace

test:
	cargo test --workspace

clean:
	cargo clean
