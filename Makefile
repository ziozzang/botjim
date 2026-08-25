BINARY := botjim
PKG     := ./cmd/botjim
VERSION ?= 0.1.0

.PHONY: build test race bench harnesses lint fmt clean release

build:
	go build -trimpath -o $(BINARY) $(PKG)

test:
	go test ./...

race:
	go test -race -count=2 ./...

# host-side harnesses (attribute preservation, kill -9 resume, docker E2E)
harnesses: build
	bash test/attrs.sh
	bash test/kill9.sh 6
	bash test/containers.sh

bench: build
	bash test/bench.sh

fmt:
	gofmt -w .

lint:
	go vet ./...
	@test -z "$$(gofmt -l .)" || (echo "unformatted files:"; gofmt -l .; exit 1)

clean:
	rm -f $(BINARY)
	rm -rf dist

release: lint test
	VERSION=$(VERSION) scripts/build-release.sh
