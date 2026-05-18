# Install

Install from source:

```sh
go install github.com/Za1kafps/exposeguard/cmd/exposeguard@latest
```

Build a local checkout:

```sh
make build
./bin/exposeguard scan
```

Install from a local checkout:

```sh
make install-local
```

Useful development commands:

```sh
make fmt
make test
make vet
make build
```

ExposeGuard works best on Linux hosts with Docker available. It still runs without Docker, UFW, iptables, nftables or `ss`, but reports warnings when discovery commands are missing.
