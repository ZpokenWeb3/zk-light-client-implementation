cargo := $(env) cargo
rustup := $(env) rustup

NIGHTLY = nightly-2023-10-24

.PHONY: all check clean dev-deps doc fmt install test uninstall

check:
	$(cargo) +$(NIGHTLY) check --workspace

clean:
	$(cargo) +$(NIGHTLY) clean
	cd ./contracts/foundry/verifier/ && forge clean

dev-deps:
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
	$(rustup) toolchain install $(NIGHTLY)
	curl -L https://foundry.paradigm.xyz | bash
	$(shell source ~/.bashrc)
	foundryup

doc:
	$(cargo) +$(NIGHTLY) doc

fmt:
	$(cargo) +$(NIGHTLY) fmt --all -- --check
	cd ./contracts/foundry/verifier/ &&	forge fmt

test: test-foundry

test-foundry:
	cd ./contracts/foundry/verifier/ &&	forge test && forge clean