# ExposeGuard

Find accidentally exposed Docker services before attackers do.

## Problem

Docker makes it easy to publish a service with `0.0.0.0:PORT:PORT`. On a VPS, that can turn a database, cache, queue, dashboard or internal API into an internet-facing service. UFW can also be misleading because Docker manages its own firewall chains.

## Why this exists

ExposeGuard is a small infrastructure CLI for self-hosted servers. It detects risky public bindings, explains the evidence chain, and suggests safe manual fixes. It does not exploit services, brute force credentials, modify firewall rules, send telemetry or call external services.

## Quick start

```sh
go run ./cmd/exposeguard scan
```

Build locally:

```sh
make build
./bin/exposeguard scan
```

Scan with Compose context:

```sh
./bin/exposeguard scan --compose-file docker-compose.yml --format terminal --verbose
```

## Installation

From source:

```sh
go install github.com/Za1kafps/exposeguard/cmd/exposeguard@latest
```

Local checkout:

```sh
make install-local
```

## Usage

```sh
exposeguard scan [flags]
```

Flags:

```text
--format terminal|json|markdown|sarif
--output <path>
--compose-file <path>
--no-docker
--no-firewall
--no-listeners
--fail-on critical|high|medium|low|none
--verbose
```

Exit codes:

```text
0  scan completed, no findings at or above fail threshold
1  scan completed, findings matched fail threshold
2  runtime or configuration error
```

## Example output

```text
CRITICAL
  EG-CRITICAL-001 PostgreSQL is publicly exposed
    Binding: 0.0.0.0:5432/tcp
    Chain: compose db -> container project-db-1 -> published 0.0.0.0:5432->5432/tcp -> firewall evidence -> listener evidence -> risk database
    Reason: PostgreSQL is bound to a public interface on port 5432.
    Fix: Keep dependent containers on the same Docker network and avoid publishing this service to the host.
```

## Evidence chain

Each finding is built as an exposure chain:

```text
Compose service -> Docker container -> published port -> firewall evidence -> listener evidence -> risk -> safe fix
```

The chain keeps Compose metadata, Docker metadata, firewall observations, listener observations, inferred service intent and safe fix suggestions together. Environment values are never reported; only environment key names may appear.

## Compose-aware fixes

When a Compose file is provided, ExposeGuard suggests fixes that fit the service intent:

- Databases, caches, queues, storage and search engines: remove public ports and use internal Docker networks.
- Admin dashboards: use a protected reverse proxy with TLS/auth, or bind to `127.0.0.1` for tunnel access.
- Public web frontends: public `80/443` can be acceptable when the service is clearly the intended edge.
- Internal APIs: remove public ports and use `expose` plus a shared internal network.
- Unknown services: make the binding local-only or remove the published port until intent is confirmed.

## Reverse proxy bypass detection

ExposeGuard looks for reverse proxy context from service names, images, labels, edge ports and shared Docker networks. If a backend, dashboard, database or cache is on the proxy network but also publishes a public host port, it reports a bypass finding:

```text
EG-HIGH-006 Backend is reachable directly, bypassing the reverse proxy
```

The safe pattern is to publish only the proxy on `80/443`, keep backends on the shared Docker network, and use `expose` for backend container ports.

## SARIF / GitHub Code Scanning

Write SARIF 2.1.0 for GitHub Code Scanning:

```sh
exposeguard scan --compose-file docker-compose.yml --format sarif --output exposeguard.sarif --fail-on none
```

Example workflow:

```yaml
name: ExposeGuard

on:
  pull_request:
  push:

permissions:
  contents: read
  security-events: write

jobs:
  exposeguard:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - name: Build ExposeGuard
        run: go build -o exposeguard ./cmd/exposeguard
      - name: Run ExposeGuard SARIF scan
        run: ./exposeguard scan --compose-file docker-compose.yml --format sarif --output exposeguard.sarif --fail-on none
      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v4
        with:
          sarif_file: exposeguard.sarif
          category: exposeguard
```

## Supported checks

- Docker container discovery through `docker ps` and `docker inspect`.
- Published Docker port parsing, including host IP, host port, container port and protocol.
- Public versus localhost binding classification.
- Optional Docker Compose context: ports, expose, networks, network mode, privileged mode, volumes, labels and environment keys.
- Service intent inference from names, images, ports, labels, environment keys, volumes, command metadata and healthcheck metadata.
- UFW status and default incoming policy detection.
- Docker iptables chain and DOCKER-USER chain detection.
- Docker-related nftables rule detection as best effort.
- Local listener discovery through `ss -tulpen`.

## Architecture

ExposeGuard is wired through small Fx modules. `internal/app` is the composition root, discovery packages provide infrastructure adapters, `internal/scan` is the scan use case, and `internal/rules`, `internal/intent`, `internal/fixes` and `internal/model` hold the domain logic. The CLI stays thin: parse flags, call the app, render or write the report, and return the documented exit code.

## Severity model

Critical:

- PostgreSQL on `5432`.
- MySQL or MariaDB on `3306`.
- Redis on `6379`.
- MongoDB on `27017`.
- Docker daemon on `2375` or `2376`.

High:

- Portainer, Grafana, Prometheus, Elasticsearch and RabbitMQ management.
- Public services with dashboard, admin, panel or manager naming.
- Public dashboards with the Docker socket mounted.
- Reverse proxy bypass for internal services.

Medium:

- Unknown public Docker services.
- Direct HTTP/HTTPS exposure without known reverse proxy context.
- Compose services using `network_mode: host`.

Low and info:

- Localhost-only bindings.
- Internal-only Docker exposure.
- Unknown firewall state.
- Docker unavailable or no published ports found.

## Docker and UFW notes

Docker can publish ports by inserting firewall rules outside the normal UFW application rule flow. A service may be reachable even when UFW appears restrictive. ExposeGuard reports Docker firewall evidence when it can read iptables or nftables rules, but it never changes firewall policy.

For many self-hosted services, the safer pattern is no published port:

```yaml
expose:
  - "3000"
```

or a loopback-only binding:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

## Output formats

Terminal output is meant for operators. JSON output has a stable schema for automation. Markdown output is GitHub-friendly for tickets and audit notes. SARIF output integrates with GitHub Code Scanning.

## Examples

See:

- `examples/exposed-postgres/docker-compose.yml`
- `examples/exposed-redis/docker-compose.yml`
- `examples/exposed-portainer/docker-compose.yml`
- `examples/safe-compose/docker-compose.yml`

## Non-goals

- Exploitation or credential checks.
- Brute force, fuzzing or offensive scanning.
- Destructive auto-fixes.
- Automatic firewall changes.
- External telemetry or SaaS reporting.
- Reading unrelated local files.