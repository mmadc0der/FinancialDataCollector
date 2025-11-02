.PHONY: all build run test unit it it-producer coverage cover-html lint fmt clean producer

APP:=kernel
BIN:=bin/$(APP)
TIMEOUT?=30m

# Optional package selector for tests, e.g. `make unit PKG=./internal/protocol`
# When empty, unit tests run across all packages except integration tests under ./internal/it
PKG?=

# Package lists (Linux/macOS shells). On Windows without a Unix shell, run the commands directly.
PKGS_ALL:=$(shell go list ./...)
PKGS_UNIT:=$(shell echo "$(PKGS_ALL)" | tr ' ' '\n' | grep -v "/tests/integration$$" | grep -v "/tests/producer$$" | grep -v "/modules.d/producer-example$$")

all: build

build:
	mkdir -p bin
	GO111MODULE=on go build -o $(BIN) ./cmd/kernel

run: build
	./$(BIN) --config ./config/kernel.yaml | cat

producer:
	go run ./modules.d/producer-example

test:
	go test -race -cover ./...

# Run unit tests only (excludes integration tests under ./internal/it)
unit:
ifeq ($(strip $(PKG)),)
	go test -race -cover -covermode=atomic $(PKGS_UNIT)
else
	go test -race -cover -covermode=atomic $(PKG)
endif

# Run integration tests (requires Docker). Set RUN_IT=1 to enable tests.
it:
	RUN_IT=1 go test -tags=integration -race -v -cover -covermode=atomic -coverpkg=./... -timeout $(TIMEOUT) ./tests/integration

# Run producer-side integration tests (requires Docker). Set RUN_IT=1 RUN_PRODUCER=1.
it-producer:
	RUN_IT=1 RUN_PRODUCER=1 go test -tags="integration producer" -race -v -cover -covermode=atomic -coverpkg=./... -timeout $(TIMEOUT) ./tests/producer

# Aggregate coverage using Go's coverage data directories (Go 1.20+).
# - Produces coverage.out (text) and coverage.html (HTML report).
coverage:
	rm -rf coverage coverage.out coverage.html
ifeq ($(strip $(PKG)),)
	GOCOVERDIR=coverage go test -race -cover -covermode=atomic $(PKGS_UNIT)
else
	GOCOVERDIR=coverage go test -race -cover -covermode=atomic $(PKG)
endif
	RUN_IT=1 GOCOVERDIR=coverage go test -tags=integration -race -cover -covermode=atomic -coverpkg=./... -timeout $(TIMEOUT) ./tests/integration || true
	RUN_IT=1 RUN_PRODUCER=1 GOCOVERDIR=coverage go test -tags="integration producer" -race -cover -covermode=atomic -coverpkg=./... -timeout $(TIMEOUT) ./tests/producer || true
	go tool covdata textfmt -i=coverage -o coverage.out
	@echo "Wrote coverage.out"
	go tool cover -html=coverage.out -o coverage.html
	@echo "Open coverage.html in a browser to view annotated coverage"

lint:
	go vet ./...

fmt:
	go fmt ./...

clean:
	rm -rf bin dist coverage coverage.out coverage.html

