# SARIF

ExposeGuard can write SARIF 2.1.0 for GitHub Code Scanning:

```sh
exposeguard scan --compose-file docker-compose.yml --format sarif --output exposeguard.sarif --fail-on none
```

Severity mapping:

| ExposeGuard | SARIF level |
| --- | --- |
| critical | error |
| high | error |
| medium | warning |
| low | note |
| info | note |

SARIF results include stable rule IDs, a message with reason, impact and a short fix, Compose file locations when available, and properties such as service name, container name, ports, binding, intent and confidence.

GitHub Actions example:

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
