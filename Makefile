CARGO ?= cargo

.DEFAULT_GOAL := help

.PHONY: help ci check fmt fmt-check lint test feature-check docs security package coverage tools clean

help: ## Show available targets
	@awk 'BEGIN {FS = ":.*##"; printf "%-18s %s\n", "Target", "Purpose"} /^[a-zA-Z_-]+:.*##/ {printf "%-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

ci: check test feature-check security package ## Run the full local CI contract

check: fmt-check lint docs ## Run fast quality checks
	$(CARGO) check --all-targets --locked
	$(CARGO) check --all-targets --no-default-features --locked

fmt: ## Format Rust sources
	$(CARGO) fmt --all

fmt-check: ## Verify Rust formatting
	$(CARGO) fmt --all -- --check

lint: ## Run Clippy across every target and feature
	$(CARGO) clippy --all-targets --all-features --locked -- -D warnings

test: ## Run the all-feature test suite
	$(CARGO) test --all-features --locked

feature-check: ## Check feature combinations with cargo-hack
	$(CARGO) hack check --feature-powerset --depth 2 --locked

docs: ## Build API documentation with warnings denied
	RUSTDOCFLAGS="-D warnings --cfg docsrs" $(CARGO) doc --all-features --no-deps --locked

security: ## Enforce RustSec and dependency policy
	$(CARGO) audit --deny warnings
	$(CARGO) deny check

package: ## Verify the crates.io source package
	$(CARGO) package --locked

coverage: ## Generate HTML coverage with cargo-llvm-cov
	$(CARGO) llvm-cov --workspace --all-features --locked --html

tools: ## Install the pinned Cargo tools used by CI
	$(CARGO) install --locked cargo-audit@0.22.2
	$(CARGO) install --locked cargo-deny@0.20.2
	$(CARGO) install --locked cargo-hack@0.6.45
	$(CARGO) install --locked cargo-llvm-cov@0.8.7
	$(CARGO) install --locked cargo-semver-checks@0.49.0

clean: ## Remove Cargo build output
	$(CARGO) clean
