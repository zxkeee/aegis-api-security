.PHONY: build run test clean docker loadgen check-binaries hooks

build:
	go build -ldflags="-s -w" -o bin/gateway ./cmd/gateway

# Build the load/outage generator into bin/ (gitignored) so it never lands as a
# stray binary in the repo root, the way `go build ./tests/load` does.
loadgen:
	go build -o bin/loadgen ./tests/load

# Fail if a compiled binary or oversized blob got committed. Also runs in CI.
check-binaries:
	./scripts/check-no-binaries.sh

# Install the versioned git hooks (.githooks/) for this clone.
hooks:
	git config core.hooksPath .githooks
	@echo "git hooks installed: core.hooksPath -> .githooks"

run: build
	./bin/gateway --config config/gateway.yaml

test:
	go test ./... -v -race

clean:
	rm -rf bin/

docker:
	docker compose up -d --build

docker-down:
	docker compose down

lint:
	golangci-lint run ./...

fmt:
	go fmt ./...
	goimports -w .
