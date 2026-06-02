# Evidence Chain

ExposeGuard findings are evidence chains, not isolated alerts.

```text
Compose service -> Docker container -> published port -> firewall evidence -> listener evidence -> risk -> safe fix
```

The scanner keeps each step explicit:

- Compose context: service name, image, ports, expose entries, networks, labels, volumes and environment keys.
- Docker context: container name, image, state, labels, networks, mounts and published ports.
- Firewall context: UFW state, default policy and Docker-related iptables or nftables evidence.
- Listener context: best-effort `ss -tulpen` listener evidence.
- Inference context: service intent, confidence and the signals used.

Environment values are not reported. Command and healthcheck values are used only as weak inference signals and are shown as configured, not printed.

The goal is to answer why a service is reachable and what manual fix is safe.
