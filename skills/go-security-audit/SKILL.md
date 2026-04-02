---
name: go-security-audit
description: Perform a comprehensive security audit of a Golang project. Use this skill whenever the user wants to audit Go code for vulnerabilities, find security issues in a Go codebase, review Go code against security best practices, identify attack surfaces in a Go service, check for SQL injection / SSRF / command injection / auth bypass / race conditions in Go, produce a security vulnerability report with CVE-style findings, or run a Go secure code review. Trigger this skill even if the user just says "check my Go code for security issues", "audit this Go project", or "find vulnerabilities in this Go service".
---

# Go Security Audit

A skill for performing deep, structured security audits of Golang projects. The audit follows a four-phase methodology: **project reconnaissance** → **attack surface mapping** → **code-level vulnerability analysis** → **report generation**, and always produces a structured vulnerability report.

---

## Environment Setup & Tool Availability

> **Complete this section before starting the audit.** The core audit (manual code reading and analysis) runs in any environment without network access. The optional helper tools enhance coverage but are not required.

This skill can invoke three optional static analysis tools to supplement manual review:

| Tool | Purpose | Required? |
|---|---|---|
| `govulncheck` | Scan go.mod dependencies for known CVEs | Optional |
| `gosec` | Go SAST — automatically detect common security patterns | Optional |
| `staticcheck` | Go static analysis with security-related checks | Optional |

### Environment Detection

Before starting the audit, check tool availability:

```bash
command -v govulncheck && govulncheck --version || echo "[not installed] govulncheck"
command -v gosec       && gosec --version       || echo "[not installed] gosec"
command -v staticcheck && staticcheck --version  || echo "[not installed] staticcheck"
```

### With Network Access: One-line Install

```bash
bash skills/go-security-audit/scripts/install_tools.sh
```

### Offline / Air-gapped Environment

If the target machine has no internet access, pre-compile the tools on a **connected machine with the same OS and architecture**, then transfer the binaries:

```bash
# On the connected machine
GOBIN=/tmp/audit-tools go install golang.org/x/vuln/cmd/govulncheck@latest
GOBIN=/tmp/audit-tools go install github.com/securego/gosec/v2/cmd/gosec@latest
GOBIN=/tmp/audit-tools go install honnef.co/go/tools/cmd/staticcheck@latest

# Package and transfer
tar -czf audit-tools.tar.gz -C /tmp audit-tools

# On the target machine
tar -xzf audit-tools.tar.gz
sudo cp audit-tools/* /usr/local/bin/ && chmod +x /usr/local/bin/govulncheck /usr/local/bin/gosec /usr/local/bin/staticcheck
```

> For detailed offline options (Docker image, internal GOPROXY, local vulnerability database for govulncheck), see `references/offline-setup.md`.

### Behavior When Tools Are Unavailable

If none of the tools can be installed, **the skill continues to run in full** — all four phases proceed using manual code reading and pattern matching. The report appendix will note which tools were not run and recommend running them when the environment allows.

---

## Phase 1 — Project Reconnaissance

Before looking for vulnerabilities, understand what you're auditing.

### 1.1 Framework & Dependency Analysis

- Read `go.mod` and `go.sum`. Identify:
  - Web framework (net/http, Gin, Echo, Fiber, Chi, Gorilla, gRPC, …)
  - ORM / DB drivers (GORM, sqlx, database/sql, mongo-driver, redis, …)
  - Auth libraries (jwt-go, golang-jwt, oauth2, casbin, …)
  - Crypto libraries (bcrypt, x/crypto, …)
  - External HTTP clients (resty, fasthttp, …)
  - Config / secret loaders (viper, envconfig, godotenv, …)
- Note any dependencies with known CVEs (cross-reference GHSA / NVD naming conventions by package name and major version).
- If `govulncheck` is available, run it as the first dependency scan step:
  ```bash
  govulncheck ./...
  ```

### 1.2 Project Structure

- Map the directory tree: `cmd/`, `internal/`, `pkg/`, `api/`, `handler/`, `middleware/`, `model/`, `repository/`, `service/`, `config/`, etc.
- Identify entry points: `main.go`, CLI commands, HTTP server setup, gRPC server registration.
- Identify config and secret handling: env vars, config files, Vault/AWS Secrets Manager integration.

### 1.3 Build a Reconnaissance Summary

Write a short (10–20 line) summary covering:
- Application type (REST API, gRPC service, CLI, worker, …)
- Tech stack and key dependencies
- Deployment context clues (Dockerfile, k8s manifests, CI config)
- Lines of Go code (rough estimate from file count × avg size)

---

## Phase 2 — Attack Surface Mapping

Identify every place where **untrusted input enters the system** and every **privileged operation**.

### Entry Points to Examine

| Entry Point Category | What to Look For |
|---|---|
| HTTP handlers | Route registration, request body parsing, URL params, headers, cookies |
| WebSocket handlers | Upgrade logic, message parsing |
| gRPC methods | Unary and stream handlers, metadata extraction |
| CLI args | `os.Args`, flag parsing, subcommand dispatch |
| File ingestion | Upload handlers, file path construction |
| Message queues | Kafka/RabbitMQ/NATS consumers, SQS handlers |
| Scheduled jobs / cron | Trigger inputs, job parameters |
| Environment / config | Values read from env or config files used in sensitive operations |

### High-Risk Modules to Flag

List modules (files or packages) that:
- Execute OS commands (`exec.Command`, `syscall.Exec`)
- Construct SQL queries (especially string concatenation)
- Make outbound HTTP/TCP calls based on user input
- Handle authentication / authorization tokens
- Perform file I/O with user-controlled paths
- Deserialize untrusted data (JSON, XML, gob, protobuf with dynamic types)
- Manage goroutines/channels shared across requests (concurrency state)

Read `references/go-security-rules.md` for the full checklist of vulnerability patterns to look for in each category.

---

## Phase 3 — Code-Level Vulnerability Analysis

Audit the code systematically. For every high-risk module and entry point identified in Phase 2, trace data flows from input to sensitive operation.

### Helper Tool Scans (If Available)

If the tools are installed, run them before the manual audit and use the results as additional leads:

```bash
# SAST scan (save output for reference)
gosec -fmt=json -out=gosec-results.json ./... 2>/dev/null || gosec ./...

# Static analysis
staticcheck ./...

# Race detector (requires the project to compile and have tests)
go test -race ./... 2>&1 | grep -E "DATA RACE|FAIL|ok"
```

Treat tool output as **supplementary input only** — SAST tools have both false positives and false negatives. Manually confirm whether each flagged item is genuinely exploitable.

### Manual Code Audit

Work through each vulnerability category listed in `references/go-security-rules.md`. For each category, search for the specific Go patterns described there. Use code search tools (Grep, Glob) extensively — don't just skim.

### Tracing Call Chains

For every finding, reconstruct the **full call chain** from the entry point to the vulnerable code location:

```
HTTP POST /api/v1/users
  → handler.CreateUser()            [handlers/user.go:42]
    → service.UserService.Create()  [service/user.go:88]
      → repo.UserRepo.Insert()      [repository/user.go:31]
        → db.QueryContext(ctx, "INSERT INTO users WHERE id="+id)  ← VULNERABLE
```

Trace through middleware too — missing auth middleware is itself a finding.

### Severity Rating

| Severity | Criteria |
|---|---|
| Critical | Direct RCE, authentication bypass, plaintext credential exposure |
| High | SQLi, SSRF, path traversal, broken access control, insecure deserialization |
| Medium | IDOR without impact amplifier, weak crypto, missing rate limiting on sensitive endpoints, verbose errors leaking internals |
| Low | Timing side-channels, unnecessary data exposure in logs, missing security headers |
| Informational | Code style issues with minor security implications, outdated dependencies without known exploits |

---

## Phase 4 — Vulnerability Report

Read `references/report-template.md` for the exact report structure to use.

The report MUST include, for every finding:

1. **Vulnerability name** — a clear, descriptive title (e.g., "SQL Injection in User Search Endpoint")
2. **Severity** — Critical / High / Medium / Low / Informational
3. **Vulnerable code snippet** — exact file path and line numbers, with the relevant code block
4. **Call chain** — the full path from entry point to vulnerable line
5. **Root cause** — one-paragraph explanation of *why* the code is vulnerable (not just *what* it does wrong)
6. **Proof of Concept (PoC)** — a concrete exploit payload or request demonstrating exploitability; for non-exploitable issues (e.g., missing header), a description of the attack scenario
7. **Remediation** — specific Go code or pattern to fix the issue

Always produce:
- An **Executive Summary** (project overview, total findings by severity, overall risk posture)
- A **Finding Summary Table** (all findings in one place for quick scanning)
- **Detailed Findings** (one section per finding with all 7 fields above)
- An **Appendix** with the full tech stack inventory and a note on which helper tools were run

---

## Workflow

1. **Environment check** — Detect whether the three helper tools are installed. Install via the script if network is available; skip gracefully if not.
2. **Reconnaissance** — Read go.mod, scan directory structure, write the reconnaissance summary. Run `govulncheck` if available.
3. **Attack surface map** — List all entry points and flag high-risk modules.
4. **Helper scans** — Run `gosec` and `staticcheck` if available; collect results as reference leads.
5. **Manual audit** — Go through each high-risk module using the rules in `references/go-security-rules.md`.
6. **Report** — Write the full report following the structure in `references/report-template.md`. Save it as `security-audit-report.md` in the project root (or a location the user specifies).

If the codebase is large (>50 Go files), prioritize: entry-point handlers → auth/authz middleware → DB/query layer → file operations → outbound HTTP → config/secret loading.

If the user provides a specific area of concern ("focus on the payment module"), prioritize that but still do a lighter pass on the full codebase.

---

## Reference files

- `references/go-security-rules.md` — Full checklist of Go-specific vulnerability patterns, detection heuristics, and Go standard library pitfalls. Read when auditing each vulnerability category.
- `references/report-template.md` — Exact Markdown template to use when writing the output report.
- `references/offline-setup.md` — Detailed options for installing helper tools in offline/air-gapped environments (Docker image, internal GOPROXY, local vulnerability database).
- `scripts/install_tools.sh` — One-line install script for all three helper tools (use when network is available).
