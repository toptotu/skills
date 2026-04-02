# Vulnerability Report Template

Use this exact structure for every Go security audit report. Replace placeholder text in `[brackets]`.

---

```markdown
# Go Security Audit Report — [Project Name]

**Audit Date:** [YYYY-MM-DD]  
**Audited By:** Claude (go-security-audit skill)  
**Repository:** [path or URL]  
**Go Version:** [from go.mod]  
**Scope:** [Full codebase / specific packages / specific modules]

---

## Executive Summary

[2–4 paragraph summary covering:
- What the application does and its deployment context
- Overall security posture (e.g., "The service presents a high-risk attack surface due to…")
- Total number of findings broken down by severity
- The most critical issues and their potential business impact
- Whether the codebase follows Go security best practices overall]

### Finding Summary

| ID | Title | Severity | Location |
|---|---|---|---|
| GSEC-001 | [Vulnerability Title] | Critical | [file:line] |
| GSEC-002 | [Vulnerability Title] | High | [file:line] |
| GSEC-003 | [Vulnerability Title] | Medium | [file:line] |
| ... | ... | ... | ... |

**Severity Breakdown:**  
🔴 Critical: N  |  🟠 High: N  |  🟡 Medium: N  |  🔵 Low: N  |  ℹ️ Informational: N

---

## Project Reconnaissance

### Tech Stack

| Category | Component | Version |
|---|---|---|
| Language | Go | [version] |
| Web Framework | [e.g., Gin] | [version] |
| ORM / DB Driver | [e.g., GORM + PostgreSQL] | [version] |
| Auth | [e.g., golang-jwt/jwt] | [version] |
| Config | [e.g., viper] | [version] |
| ... | ... | ... |

### Application Overview

[Short description: type of service, main functionality, how it handles requests, deployment context (containerized, cloud, etc.)]

### Entry Points

| Entry Point | Type | Handler | File |
|---|---|---|---|
| POST /api/v1/login | HTTP | AuthHandler.Login | handlers/auth.go |
| GET /api/v1/users/:id | HTTP | UserHandler.Get | handlers/user.go |
| ... | ... | ... | ... |

---

## Detailed Findings

---

### GSEC-001 — [Vulnerability Title]

**Severity:** 🔴 Critical / 🟠 High / 🟡 Medium / 🔵 Low / ℹ️ Informational  
**Category:** [e.g., SQL Injection / SSRF / Command Injection / …]  
**Location:** `[file/path.go:line_start–line_end]`

#### Vulnerable Code

```go
// [file/path.go:line_start–line_end]
[Exact code snippet showing the vulnerability.
Include enough context (5–15 lines) to understand the problem.
Mark the vulnerable line with a comment like: // ← VULNERABLE]
```

#### Call Chain

```
[Entry point, e.g.: HTTP POST /api/v1/search]
  → [HandlerFunc name]()           [handlers/search.go:NN]
    → [ServiceFunc name]()         [service/search.go:NN]
      → [RepoFunc name]()          [repository/search.go:NN]
        → [vulnerable expression]  ← VULNERABLE
```

#### Root Cause

[One clear paragraph explaining *why* this code is vulnerable. Describe the programming mistake or missing control, not just the symptom. For example: "The `UserID` parameter is extracted from the query string and interpolated directly into the SQL string using `fmt.Sprintf`. Go's `database/sql` package only provides parameterized query protection when the `?` placeholder syntax is used; string interpolation bypasses the driver's parameterization entirely, allowing an attacker to inject arbitrary SQL."]

#### Proof of Concept (PoC)

[Concrete, actionable exploit. Choose the appropriate format:]

**For injection vulnerabilities — HTTP request:**
```http
POST /api/v1/search HTTP/1.1
Host: target.example.com
Content-Type: application/json
Authorization: Bearer <valid_token>

{
  "query": "' OR '1'='1'; DROP TABLE users;--"
}
```

**Expected result:** [e.g., "Returns all user records regardless of ownership; the DROP TABLE statement executes if the DB user has DDL privileges."]

**For SSRF — HTTP request:**
```http
GET /api/v1/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ HTTP/1.1
Host: target.example.com
Authorization: Bearer <valid_token>
```

**Expected result:** [e.g., "The server fetches the AWS metadata endpoint and returns the IAM role credentials in the response body."]

**For auth bypass — description:**
[Describe the attacker scenario, what they send, and what they gain access to.]

**For race condition — description:**
[Describe the concurrent request pattern and the inconsistent state it creates.]

#### Remediation

[Specific fix with Go code example:]

```go
// Recommended fix
[corrected code snippet showing the safe pattern]
```

[Brief explanation of why the fix addresses the root cause.]

---

### GSEC-002 — [Next Vulnerability]

[Repeat the same structure above]

---

## Appendix

### A. Full Dependency Inventory

| Package | Version | Role | Security Notes |
|---|---|---|---|
| [package/path] | [vX.Y.Z] | [e.g., HTTP router] | [e.g., No known CVEs] |
| [package/path] | [vX.Y.Z] | [e.g., JWT library] | [e.g., CVE-2020-26160 if dgrijalva/jwt-go] |

### B. Files Not Audited

[List any files/packages excluded from scope and why, e.g., "vendor/ directory", "generated protobuf files".]

### C. Testing Recommendations

[Suggest dynamic testing to verify the findings, e.g.:]
- Run `go test -race ./...` to surface data races.
- Use `govulncheck ./...` to scan for known CVEs in dependencies.
- Run SAST tools: `gosec ./...`, `staticcheck ./...`.
- For SSRF findings: test with an internal HTTP listener (e.g., Burp Collaborator or interactsh).
```

---

## Severity Icon Reference

Use these consistently throughout the report:

| Severity | Icon | When to Use |
|---|---|---|
| Critical | 🔴 | RCE, auth bypass, plaintext credential storage |
| High | 🟠 | SQLi, SSRF, path traversal, broken access control |
| Medium | 🟡 | IDOR, weak crypto, missing rate limiting, info leakage |
| Low | 🔵 | Minor hardening gaps, missing headers, verbose errors |
| Informational | ℹ️ | Style issues, low-impact observations |

## Notes for Report Quality

- Every finding MUST have all seven sections: title, severity, code snippet, call chain, root cause, PoC, remediation.
- Code snippets must include the exact file path and line numbers as a comment.
- Call chains must be traced from the HTTP/gRPC/CLI entry point all the way to the vulnerable operation — do not stop at the handler.
- PoCs must be concrete — vague "an attacker could..." statements without a payload are not acceptable.
- Root causes must explain the *mechanism* of the vulnerability, not just describe what the code does.
- Remediations must include working Go code, not just advice.
