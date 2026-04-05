.PHONY: help build test test-offline clippy fmt lint coverage examples clean

# Default flags — override on the command line if needed
FEATURES ?= vendored
FEATURES_FLAG = $(if $(FEATURES),--features $(FEATURES),)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2}'

build: ## Build the full workspace
	cargo build --workspace $(FEATURES_FLAG)

test: ## Run all tests including network-dependent ones
	cargo test --workspace $(FEATURES_FLAG) -- --include-ignored

test-offline: ## Run only offline (non-ignored) tests
	cargo test --workspace $(FEATURES_FLAG)

clippy: ## Lint with clippy (warnings are errors)
	cargo clippy --workspace --tests --examples $(FEATURES_FLAG) -- -D warnings

fmt: ## Check formatting
	cargo fmt --all -- --check

lint: fmt clippy ## Run fmt check and clippy

coverage: ## Generate coverage report (requires cargo-llvm-cov)
	LLVM_COV_FLAGS="--show-branch-summary=false" \
	cargo llvm-cov --workspace $(FEATURES_FLAG) -- --include-ignored

examples: ## Run all examples
	cargo run -p c-ares $(FEATURES_FLAG) --example dnsrec
	cargo run -p c-ares $(FEATURES_FLAG) --example epoll
	cargo run -p c-ares $(FEATURES_FLAG) --example select
	cargo run -p c-ares $(FEATURES_FLAG) --example version
	cargo run -p c-ares-resolver $(FEATURES_FLAG) --example blocking
	cargo run -p c-ares-resolver $(FEATURES_FLAG) --example callback
	cargo run -p c-ares-resolver $(FEATURES_FLAG) --example futures
	cargo run -p c-ares-resolver $(FEATURES_FLAG) --example send_dnsrec

clean: ## Remove build artifacts
	cargo clean
