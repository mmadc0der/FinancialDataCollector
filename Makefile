.PHONY: all build run test lint fmt clean

APP:=kernel
BIN:=bin/$(APP)

all: build

build:
	mkdir -p bin
	GO111MODULE=on go build -o $(BIN) ./cmd/kernel

run: build
	./$(BIN) --config ./config/kernel.yaml | cat

test:
	go test -race -cover ./...

lint:
	go vet ./...

fmt:
	go fmt ./...

clean:
	rm -rf bin dist coverage.out

