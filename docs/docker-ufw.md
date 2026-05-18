# Docker and UFW

Docker publishes ports by programming host networking rules. On many systems this happens through iptables chains such as `DOCKER` and `DOCKER-USER`. UFW may still be active, but traffic to Docker-published ports can behave differently than ordinary host services.

ExposeGuard checks:

- `ufw status`
- `ufw status verbose`
- `iptables-save`
- `nft list ruleset`

Failures are warnings, not fatal errors. Some commands need root privileges to show complete evidence.

Safer patterns:

```yaml
ports:
  - "127.0.0.1:5432:5432"
```

or no published port at all:

```yaml
expose:
  - "5432"
```

Use `DOCKER-USER` or an equivalent host policy when a service must be reachable only from known source networks.
