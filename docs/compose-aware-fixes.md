# Compose-Aware Fixes

When `--compose-file` is provided, ExposeGuard uses Compose metadata to suggest fixes that fit the service.

For databases, caches, queues, storage and search engines, the preferred fix is to remove public ports:

```yaml
expose:
  - "5432"
```

Then put dependent services on the same Docker network.

If host-only access is needed, bind the port to loopback:

```yaml
ports:
  - "127.0.0.1:5432:5432/tcp"
```

For dashboards, prefer a reverse proxy with TLS and authentication. For local tunnel access, loopback binding is acceptable.

For internal APIs behind a proxy, remove `ports` and use `expose` plus a shared internal network. Publish only the proxy.

For unknown services, ExposeGuard stays conservative. It suggests local-only binding or removing the published port until the service intent is confirmed.
