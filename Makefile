.PHONY: all build run test test-unit test-integration lint fmt clean

APP:=kernel
BIN:=bin/$(APP)

all: build

build:
	mkdir -p bin
	GO111MODULE=on go build -o $(BIN) ./cmd/kernel

run: build
	./$(BIN) --config ./config/kernel.yaml | cat

test: test-unit

test-unit:
	go test -race -cover ./...

test-integration:
	go test -race -cover -tags=integration ./...

lint:
	go vet ./...

fmt:
	go fmt ./...

clean:
	rm -rf bin dist coverage.out

