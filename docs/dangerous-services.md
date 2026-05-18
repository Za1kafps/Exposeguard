# Dangerous Services

ExposeGuard treats these public bindings as critical:

| Service | Port |
| --- | ---: |
| PostgreSQL | 5432 |
| MySQL or MariaDB | 3306 |
| Redis | 6379 |
| MongoDB | 27017 |
| Docker daemon | 2375, 2376 |

These services are valuable targets and are rarely safe to expose directly on a VPS.

High severity services include common admin and observability interfaces:

| Service | Port |
| --- | ---: |
| Portainer | 9000, 9443 |
| Grafana | 3000 |
| Prometheus | 9090 |
| Elasticsearch | 9200 |
| RabbitMQ management | 15672 |

Typical fixes:

```text
- Bind to 127.0.0.1 and place the service behind a protected reverse proxy.
- Remove the published port and use an internal Docker network.
- Restrict access with a VPN or strict source IP firewall rule.
```
