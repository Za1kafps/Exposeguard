# Reverse Proxy Bypass

A reverse proxy can enforce TLS, authentication, rate limits, IP filters, headers and routing. Those controls only work when traffic must pass through the proxy.

ExposeGuard reports `EG-HIGH-006` when a backend-like service has a public Docker port while reverse proxy context is present in the same Compose project or Docker network.

Signals include:

- Service or image names such as `nginx`, `traefik`, `caddy`, `haproxy` or `nginx-proxy-manager`.
- Public edge ports such as `80`, `443`, `8080` or `8443`.
- Labels such as `traefik.*`, `caddy.*`, `nginx.*` or `nginx-proxy.*`.
- Shared Docker networks between the proxy and backend.

Safer Compose shape:

```yaml
services:
  proxy:
    image: traefik:v3
    ports:
      - "80:80"
      - "443:443"
    networks:
      - edge

  api:
    image: example/api
    expose:
      - "3000"
    networks:
      - edge

networks:
  edge:
```

Do not publish the backend directly unless it is intentionally an edge service.
