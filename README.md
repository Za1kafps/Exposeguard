# ExposeGuard

Find accidentally exposed Docker services before attackers do.

## Problem

Docker makes it easy to publish a service with `0.0.0.0:PORT:PORT`. On a VPS, that can turn a database, queue, dashboard or internal admin panel into an internet-facing service. UFW can also give a false sense of safety because Docker manages its own iptables rules.

ExposeGuard answers one question:

> What is actually exposed from this host, why is it exposed, and how can it be fixed safely?

## Why this exists

ExposeGuard is a small infrastructure CLI for self-hosted servers. It detects risky public bindings, explains the evidence, and suggests safe manual fixes. It does not exploit services, brute force credentials, modify firewall rules, send telemetry or call external services.

## Quick start

```sh
go run ./cmd/exposeguard scan
```

Build locally:

```sh
make build
./bin/exposeguard scan
```

Scan with a Compose file and write Markdown:

```sh
./bin/exposeguard scan --compose-file docker-compose.yml --format markdown --output exposeguard.md
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
--format terminal|json|markdown
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
ExposeGuard scan report
Summary: 1 findings (1 critical, 0 high, 0 medium, 0 low, 0 info)

CRITICAL
  EG-CRITICAL-001 PostgreSQL is publicly exposed
    Binding: 0.0.0.0:5432/tcp
    Reason: PostgreSQL is bound to a public interface on port 5432.
    Fixes:
      - Change the compose port mapping to "127.0.0.1:5432:5432" if only local access is needed.
      - Remove the published port and place dependent services on the same Docker network.
```

## Supported checks

- Docker container discovery through `docker ps` and `docker inspect`.
- Published Docker port parsing, including host IP, host port, container port and protocol.
- Public versus localhost binding classification.
- Optional Docker Compose context: ports, expose, network mode, privileged mode, volumes, labels and environment keys.
- UFW status and default incoming policy detection.
- Docker iptables chain and DOCKER-USER chain detection.
- Docker-related nftables rule detection as best effort.
- Local listener discovery through `ss -tulpen`.

## Severity model

Critical:

- PostgreSQL on 5432.
- MySQL or MariaDB on 3306.
- Redis on 6379.
- MongoDB on 27017.
- Docker daemon on 2375 or 2376.

High:

- Portainer, Grafana, Prometheus, Elasticsearch and RabbitMQ management.
- Public services with dashboard, admin, panel or manager naming.
- Public dashboards with the Docker socket mounted.

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

For many self-hosted services, the safer pattern is:

```yaml
ports:
  - "127.0.0.1:3000:3000"
```

Then expose the service through a reverse proxy with TLS and authentication.

## Output formats

Terminal output is meant for operators. JSON output has a stable schema for automation. Markdown output is GitHub-friendly and useful for tickets, audits and handoff notes.

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

## Roadmap

- Better Compose project correlation.
- More reverse proxy context detection.
- SARIF output.
- Package manager releases.
- More Linux firewall backends.

## Contributing

Keep changes boring, testable and operator-friendly. Add table-driven tests for new parsing and rule behavior. User-facing output and documentation should be clear English.

## Security policy

Do not report secrets in issues. If you find a security problem in ExposeGuard itself, open a minimal private report with reproduction steps and affected versions.

## License

See `LICENSE`.
