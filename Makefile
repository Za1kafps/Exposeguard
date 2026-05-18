APP := exposeguard

.PHONY: build run test fmt fmt-check vet clean install-local

build:
	go build -o bin/$(APP) ./cmd/exposeguard

run:
	go run ./cmd/exposeguard scan

test:
	go test ./...

fmt:
	go fmt ./...

fmt-check:
	@test -z "$$(gofmt -l .)"

vet:
	go vet ./...

clean:
	rm -rf bin dist

install-local:
	go install ./cmd/exposeguard
