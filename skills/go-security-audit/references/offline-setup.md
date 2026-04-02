# Offline / Air-gapped Environment Setup

This skill uses three optional static analysis tools as supplements to manual code review: `govulncheck`, `gosec`, and `staticcheck`. These tools are **not required** — the skill performs a complete manual audit and produces a full vulnerability report even without them. But when available, they can surface additional findings and speed up the process.

---

## Tool Overview

| Tool | Purpose | Source |
|---|---|---|
| `govulncheck` | Scan go.mod dependencies for known CVEs | `golang.org/x/vuln` |
| `gosec` | Go SAST — detect common security anti-patterns | `github.com/securego/gosec` |
| `staticcheck` | Go static analysis with security-relevant checks | `honnef.co/go/tools` |

---

## Online Environment (internet access available)

Run the install script directly:

```bash
bash skills/go-security-audit/scripts/install_tools.sh
```

This uses `go install` to download and compile all three tools into `$GOPATH/bin` (default: `~/go/bin`).

---

## Offline / Air-gapped Environment

### Option 1: Pre-compile on a connected machine, transfer binaries

On a **connected machine with the same OS and CPU architecture** as the target:

```bash
GOBIN=/tmp/go-audit-tools go install golang.org/x/vuln/cmd/govulncheck@latest
GOBIN=/tmp/go-audit-tools go install github.com/securego/gosec/v2/cmd/gosec@latest
GOBIN=/tmp/go-audit-tools go install honnef.co/go/tools/cmd/staticcheck@latest
```

Package and transfer to the target machine:

```bash
# On the connected machine: package
tar -czf go-audit-tools.tar.gz -C /tmp go-audit-tools

# On the target machine: install
tar -xzf go-audit-tools.tar.gz
sudo cp go-audit-tools/* /usr/local/bin/
chmod +x /usr/local/bin/govulncheck /usr/local/bin/gosec /usr/local/bin/staticcheck
```

### Option 2: Internal GOPROXY / Module mirror

If your network has an **Athens, GOPROXY, or internal module mirror**, configure it and install normally:

```bash
export GONOSUMCHECK=*
export GOFLAGS=-mod=mod
export GOPROXY=http://<your-internal-proxy>

go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

### Option 3: Docker image (recommended for reproducibility)

Build the image on a connected machine and load it on the target. Reference Dockerfile:

```dockerfile
FROM golang:1.22-alpine AS builder
RUN go install golang.org/x/vuln/cmd/govulncheck@latest \
    && go install github.com/securego/gosec/v2/cmd/gosec@latest \
    && go install honnef.co/go/tools/cmd/staticcheck@latest

FROM alpine:3.19
COPY --from=builder /go/bin/govulncheck /usr/local/bin/
COPY --from=builder /go/bin/gosec       /usr/local/bin/
COPY --from=builder /go/bin/staticcheck /usr/local/bin/
ENTRYPOINT ["/bin/sh"]
```

Build and export on the connected machine:

```bash
docker build -t go-audit-tools:latest -f Dockerfile.audit .
docker save go-audit-tools:latest | gzip > go-audit-tools.tar.gz
```

Transfer and import on the target machine:

```bash
docker load < go-audit-tools.tar.gz
```

Run tools against the project by mounting the directory:

```bash
docker run --rm -v $(pwd):/workspace go-audit-tools:latest \
    sh -c "cd /workspace && gosec ./... 2>&1"
```

---

## Verify Installation

```bash
govulncheck --version
gosec --version
staticcheck --version
```

All three commands should print a version number. If any tool is missing, the skill will skip its scan step and note it in the report appendix.

---

## Offline Vulnerability Database for govulncheck

By default, `govulncheck` downloads the vulnerability database from `https://vuln.go.dev`. In an air-gapped environment, mirror it locally:

```bash
# On a connected machine: clone the database
git clone https://github.com/golang/vulndb /opt/vulndb

# On the target machine: point govulncheck to the local copy
export GOVULNDB=file:///opt/vulndb
govulncheck ./...
```

Alternatively, skip `govulncheck` and use only `gosec` and `staticcheck`, which have no external database dependencies.
