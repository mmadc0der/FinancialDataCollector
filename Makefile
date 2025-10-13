.PHONY: all build run test lint fmt clean producer

APP:=kernel
BIN:=bin/$(APP)

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

lint:
	go vet ./...

fmt:
	go fmt ./...

clean:
	rm -rf bin dist coverage.out

