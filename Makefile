APP := exposeguard

.PHONY: build run test fmt vet clean

build:
	go build -o bin/$(APP) ./cmd/exposeguard

run:
	go run ./cmd/exposeguard scan

test:
	go test ./...

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -rf bin dist
