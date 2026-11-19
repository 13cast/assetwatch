# AssetWatch

**AssetWatch** is a fast, modular CLI tool for web asset inventory and domain configuration monitoring, written in Go.

## Features

- **Passive Subdomain Discovery** — queries the [crt.sh](https://crt.sh) Certificate Transparency log aggregator to enumerate subdomains without sending a single packet to the target.
- **Parallel HTTP Inspection** — concurrent goroutine workers probe each subdomain for reachability, HTTP status codes, and security headers.
- **Security Header Audit** — checks for `Strict-Transport-Security`, `Content-Security-Policy`, and `X-Frame-Options`.
- **TLS Certificate Monitoring** — validates certificate chains and reports days until expiry.
- **Tech Detection** — fingerprints technologies from HTTP response headers and HTML meta tags.
- **Rich Reporting** — formatted terminal table, JSON export, and CSV export.

## Installation

### Prerequisites

- Go 1.22 or later

### Build from source

```bash
git clone https://github.com/13cast/assetwatch.git
cd assetwatch
go build -o assetwatch .
```

### Install directly

```bash
go install github.com/13cast/assetwatch@latest
```

## Usage

### Basic audit

```bash
assetwatch audit -d example.com
```

### Full options

```bash
assetwatch audit -d example.com \
  --workers 20 \
  --timeout 10s \
  --json report.json \
  --csv  report.csv \
  --verbose
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-d, --domain` | *(required)* | Root domain to audit |
| `--workers` | `10` | Number of parallel HTTP workers |
| `--timeout` | `8s` | Per-host HTTP request timeout |
| `--json` | | Save JSON report to this path |
| `--csv` | | Save CSV report to this path |
| `-v, --verbose` | `false` | Print verbose progress to stderr |

## Example output

```
Host                   Status  HSTS  CSP  XFO  TLS Days  Tech
----                   ------  ----  ---  ---  --------  ----
example.com            200     ✓     ✓    ✓    312       nginx, Bootstrap
www.example.com        200     ✓     ✗    ✓    312       nginx
mail.example.com       301     ✗     ✗    ✗    98        Apache
legacy.example.com     UNREACHABLE  ✗  ✗  ✗   0
```

## Project structure

```
assetwatch/
├── cmd/
│   └── root.go              # CLI commands and flags (cobra)
├── pkg/
│   ├── dns_enum/            # Passive subdomain discovery via crt.sh
│   ├── http_inspector/      # HTTP probing, security headers, TLS audit
│   ├── tech_detector/       # Technology fingerprinting
│   └── reporter/            # JSON, CSV, and table output
├── internal/
│   └── orchestrator/        # Audit pipeline controller
├── go.mod
└── README.md
```

## Architecture

```
assetwatch audit -d example.com
         │
         ▼
   orchestrator.Run()
         │
   ┌─────┴──────────────────────────────────┐
   │                                         │
   ▼                                         │
dns_enum.Enumerate()          (passive — no target traffic)
   │  crt.sh JSON API
   │  dedup + normalise
   │  → []string subdomains
   │                                         │
   ▼                                         │
http_inspector.InspectAll()   (N goroutine workers)
   │  HTTP/HTTPS probe
   │  TLS cert check
   │  Security headers
   │  → []HostResult
   │                                         │
   ▼                                         │
tech_detector.Detect()        (per-result)   │
   │  Header fingerprinting                  │
   │  → []string technologies                │
   │                                         │
   ▼                                         │
reporter.Report{}             ◄──────────────┘
   │
   ├── PrintTable() → stdout
   ├── WriteJSON()  → file
   └── WriteCSV()   → file
```

## Security note

AssetWatch performs **passive** subdomain discovery using public Certificate Transparency logs. The HTTP inspection phase **does** send probes to discovered hosts — ensure you have authorisation to scan the target domain before use.

## License

MIT
