# Threat Model

ExposeGuard is a defensive visibility tool for VPS and self-hosted Linux servers.

It assumes:

- The operator has shell access to the host.
- Docker may be installed.
- Firewall commands may require elevated permissions.
- Some discovery commands may be unavailable.

ExposeGuard does not:

- Probe remote hosts.
- Try credentials.
- Exploit services.
- Modify firewall rules.
- Read unrelated local files.
- Send data to external services.

The main risk it helps with is accidental exposure: a container that was meant for an internal network or reverse proxy is bound to a public interface.

The output is evidence for a human operator. Fixes are suggestions, not automatic changes.
