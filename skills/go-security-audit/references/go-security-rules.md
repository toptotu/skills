# Go Security Rules

This reference contains the complete checklist of vulnerability patterns and detection heuristics for auditing Go code. Each section maps to a vulnerability category. For each one, the detection heuristics tell you what code patterns to search for, and the notes explain the Go-specific pitfalls.

---

## Table of Contents

1. [SQL Injection](#1-sql-injection)
2. [Command Injection](#2-command-injection)
3. [Server-Side Request Forgery (SSRF)](#3-server-side-request-forgery-ssrf)
4. [Path Traversal / Arbitrary File Read-Write](#4-path-traversal--arbitrary-file-read-write)
5. [Authentication & Authorization Flaws](#5-authentication--authorization-flaws)
6. [Insecure Deserialization](#6-insecure-deserialization)
7. [Sensitive Data Exposure](#7-sensitive-data-exposure)
8. [Race Conditions & Concurrency Bugs](#8-race-conditions--concurrency-bugs)
9. [Cryptographic Weaknesses](#9-cryptographic-weaknesses)
10. [Denial of Service (DoS)](#10-denial-of-service-dos)
11. [Open Redirect](#11-open-redirect)
12. [CORS Misconfiguration](#12-cors-misconfiguration)
13. [Business Logic Vulnerabilities](#13-business-logic-vulnerabilities)
14. [Dependency & Supply Chain Risks](#14-dependency--supply-chain-risks)
15. [Error Handling & Information Leakage](#15-error-handling--information-leakage)
16. [HTTP Security Headers](#16-http-security-headers)
17. [Integer Overflow & Type Confusion](#17-integer-overflow--type-confusion)
18. [Template Injection (SSTI)](#18-template-injection-ssti)
19. [Goroutine Leak & Resource Exhaustion](#19-goroutine-leak--resource-exhaustion)
20. [Unsafe Package Misuse](#20-unsafe-package-misuse)

---

## 1. SQL Injection

**Detection heuristics — search for:**
- String concatenation directly into SQL: `"SELECT" + `, `fmt.Sprintf("SELECT`, `fmt.Sprintf("INSERT`, `fmt.Sprintf("UPDATE`, `fmt.Sprintf("DELETE`
- Raw query execution: `db.Query(`, `db.Exec(`, `db.QueryRow(`, `db.QueryContext(`, `db.ExecContext(`, `db.QueryRowContext(`
- GORM raw SQL: `.Raw(`, `.Exec(`, `.Where(fmt.Sprintf`
- sqlx: `db.Get(`, `db.Select(`, `db.NamedExec(`
- Any variable concatenated into a string that is then passed to a query method

**Safe patterns (for comparison):**
- Parameterized queries: `db.Query("SELECT * FROM t WHERE id = ?", id)`
- Named params: `db.NamedExec("INSERT INTO ... :name", map[string]interface{}{"name": name})`
- GORM ORM methods: `.Where("id = ?", id).Find(&result)`

**Go-specific pitfalls:**
- `fmt.Sprintf` is the most common injection vector in Go — it looks innocuous.
- GORM's `.Where(string)` without a placeholder is unsafe; `.Where("name = ?", name)` is safe.
- Integer type parameters passed as strings via `strconv.Itoa` then concatenated are still injectable if the source is untrusted.

---

## 2. Command Injection

**Detection heuristics — search for:**
- `exec.Command(`, `exec.CommandContext(`
- `syscall.Exec(`, `syscall.ForkExec(`
- `os/exec` import combined with user-controlled string arguments
- Shell invocation: `exec.Command("sh", "-c", userInput)`, `exec.Command("bash", "-c", ...)`
- Script runners: `exec.Command("python", userInput)`, `exec.Command("node", userInput)`

**Safe patterns:**
- Passing individual args as separate strings to `exec.Command`: `exec.Command("git", "clone", repoURL)` — this avoids shell interpretation.
- Allowlist validation before calling exec.

**Go-specific pitfalls:**
- `exec.Command("sh", "-c", input)` is always dangerous with unsanitized input.
- Even if the binary name is fixed, attacker-controlled arguments can exploit argument-injection in utilities like `curl`, `tar`, `git`, `ffmpeg`.
- Check for path injection: `exec.Command(userControlledPath, ...)`.

---

## 3. Server-Side Request Forgery (SSRF)

**Detection heuristics — search for:**
- `http.Get(`, `http.Post(`, `http.NewRequest(` where the URL is partly or fully from user input
- HTTP client libraries: `resty.`, `fasthttp.`, `http.Client{}.Do(`
- URL construction from user input: `url.Parse(userInput)`, `fmt.Sprintf("http://"+host)`
- gRPC dial with user-controlled address: `grpc.Dial(userAddress, ...)`
- Any code path where the user supplies a hostname, IP, or full URL that the server then fetches

**Safe patterns:**
- Allowlist of permitted domains/IPs before making requests.
- Resolving the hostname and checking against internal IP ranges (127.0.0.0/8, 169.254.0.0/16, 10.0.0.0/8, etc.).
- Using a custom `http.Transport` that blocks private IPs.

**Go-specific pitfalls:**
- Go's `net/http` follows redirects by default — an SSRF can be escalated by redirecting to an internal service.
- Cloud metadata endpoints (169.254.169.254) are a critical SSRF target.
- DNS rebinding: a hostname that resolves to a public IP for the check but to an internal IP for the actual request.

---

## 4. Path Traversal / Arbitrary File Read-Write

**Detection heuristics — search for:**
- `os.Open(`, `os.ReadFile(`, `ioutil.ReadFile(` with user-controlled path
- `filepath.Join(` with user-controlled components — note: `filepath.Join` does NOT prevent traversal if the input starts with `/` or contains `..`
- `http.ServeFile(`, `http.FileServer(` with user-controlled path
- `os.Create(`, `os.WriteFile(`, `ioutil.WriteFile(` with user-controlled path
- Template loading: `template.ParseFiles(userPath)`
- Archive extraction without path validation: `zip.NewReader`, `tar.NewReader` writing to disk

**Safe patterns:**
- `filepath.Clean` + asserting the result has the expected prefix: `strings.HasPrefix(filepath.Clean(fullPath), allowedBase)`
- Rejecting inputs containing `..` or absolute paths.

**Go-specific pitfalls:**
- `filepath.Join("/safe/base", "../../../etc/passwd")` still resolves to `/etc/passwd` — `filepath.Join` alone is not a sanitizer.
- Zip/tar extraction ("zip slip"): archive entries with `../` in their names overwrite arbitrary files. Always call `filepath.Clean` and validate the final path before writing.

---

## 5. Authentication & Authorization Flaws

### 5a. JWT Vulnerabilities

**Detection heuristics:**
- `jwt.Parse(` without validating `alg` — allows `alg=none` attack
- `jwt.ParseWithClaims(` — check that the `Keyfunc` rejects unexpected algorithms
- Secret keys hardcoded in source: `jwt.NewWithClaims(jwt.SigningMethodHS256, claims)` with a literal string key
- Weak secrets: keys shorter than 32 bytes
- Missing expiry claim check after parse

**Go-specific:**
- `golang-jwt/jwt` v4 and earlier: `jwt.Parse` with a `Keyfunc` that returns the key without checking `token.Method` allows algorithm confusion (e.g., RS256 → HS256 with public key as HMAC secret).
- Always assert: `if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf("unexpected signing method") }`

### 5b. Missing / Bypassed Authentication Middleware

**Detection heuristics:**
- Route groups registered without attaching the auth middleware
- Middleware added after route registration (order matters in most Go routers)
- Auth middleware that calls `next.ServeHTTP` even on auth failure (missing `return`)
- `c.Next()` called in Gin/Echo middleware regardless of auth result

### 5c. Broken Access Control / IDOR

**Detection heuristics:**
- Resource IDs taken directly from request without ownership check: `r.URL.Query().Get("user_id")` used in a DB query without verifying it matches the authenticated user
- Admin-only operations protected only by a frontend check with no server-side role validation
- Horizontal privilege escalation: user A can read/write user B's resources

### 5d. Hardcoded Credentials

**Detection heuristics:**
- `password =`, `secret =`, `apiKey =`, `token =`, `passwd =` with string literal on the right side
- Basic auth: `req.SetBasicAuth("admin", "password123")`
- Database DSN with literal password: `"postgres://user:password@host/db"`

---

## 6. Insecure Deserialization

**Detection heuristics — search for:**
- `encoding/gob` decode from untrusted input: `gob.NewDecoder(r.Body).Decode(&obj)`
- `encoding/xml` with `xml.Unmarshal(data, &obj)` — XXE is not exploitable in Go's stdlib, but XXE via external entity resolution in third-party parsers is
- `json.Unmarshal` with `interface{}` target (arbitrary type instantiation)
- `yaml.Unmarshal` (go-yaml v2) with `interface{}` — go-yaml v2 deserializes `!!python/object` tags and can call `Unmarshal` methods; use `yaml.v3` with strict type targets
- `msgpack.Unmarshal` with polymorphic types
- `proto.Unmarshal` — generally safe but check for recursive messages causing stack overflow

**Go-specific pitfalls:**
- go-yaml v2 `Unmarshal` into `interface{}` is a classic attack vector; go-yaml v3 is safer.
- Custom `UnmarshalJSON` / `UnmarshalBinary` methods on types that perform side effects (e.g., filesystem access) can be triggered by deserialization.

---

## 7. Sensitive Data Exposure

**Detection heuristics — search for:**
- Logging sensitive fields: `log.Printf("user: %+v", user)` where user struct contains password/token fields
- Struct JSON tags exposing internal fields: `json:"password"` in a struct used as an HTTP response
- Error messages containing SQL queries, stack traces, or internal IPs returned to clients
- Passwords stored as plaintext or with weak hashing (MD5, SHA1 without salt)
- `fmt.Println(password)` or `log.Println(secret)` in debug paths
- Tokens in URL query parameters (end up in logs): `GET /api?token=xxx`

**Safe patterns:**
- `json:"-"` tag on sensitive fields to exclude from JSON serialization.
- Use `bcrypt` / `argon2` for password hashing.
- Log sanitization: redact fields before logging.

---

## 8. Race Conditions & Concurrency Bugs

**Detection heuristics — search for:**
- Shared mutable state (package-level or struct-level variables) accessed from goroutines without synchronization:
  - Global `var` modified in handler functions
  - `map` reads/writes from multiple goroutines without `sync.RWMutex`
  - Slice append from concurrent goroutines
- `sync.WaitGroup` misuse: `wg.Add` inside goroutine instead of before `go` call
- `sync.Mutex` value copied (pass by pointer)
- `time.After` in goroutine loops causing goroutine leak and timer GC pressure
- Channel operations without `select` + `default` that can block indefinitely (deadlock risk)
- TOCTOU (Time of Check Time of Use): `os.Stat(path)` followed by `os.Open(path)` — another goroutine can replace the file between checks

**Go-specific pitfalls:**
- Maps are not safe for concurrent use; use `sync.Map` or a mutex-guarded map.
- Closures in goroutines capturing loop variables by reference: `for _, v := range items { go func() { use(v) }() }` — `v` is shared.
- `http.Handler` methods called concurrently; any handler-level state must be thread-safe.

---

## 9. Cryptographic Weaknesses

**Detection heuristics — search for:**
- Weak algorithms: `md5.New()`, `sha1.New()`, `des.NewCipher(`, `rc4.NewCipher(`
- ECB mode: `cipher.NewCBCEncrypter` / `cipher.NewCBCDecrypter` — not ECB itself, but check for CBC without HMAC (padding oracle)
- Static/hardcoded IV or nonce: `iv := []byte("0000000000000000")`
- `math/rand` used for security-sensitive operations (token generation, nonce, OTP): `rand.Intn(`, `rand.Read(` from `math/rand` (not `crypto/rand`)
- RSA encryption without OAEP: `rsa.EncryptPKCS1v15(`
- TLS config with `InsecureSkipVerify: true`
- TLS min version below 1.2: `MinVersion: tls.VersionTLS10`
- Weak key size: RSA < 2048 bits, ECDSA with P-224

**Safe alternatives:**
- `crypto/rand` for random bytes; `rand.Reader` as entropy source.
- AES-GCM for authenticated encryption.
- `argon2id` or `bcrypt` for passwords.
- `sha256` / `sha3` for hashing.

---

## 10. Denial of Service (DoS)

**Detection heuristics — search for:**
- Missing request body size limit: `json.NewDecoder(r.Body).Decode(&v)` without `http.MaxBytesReader`
- Unbounded regex on user input: `regexp.MustCompile(userPattern)` (ReDoS)
- Unbounded loop driven by user-controlled value: `for i := 0; i < userCount; i++`
- Unbounded memory allocation: `make([]byte, userSize)`
- No read deadline on connections: `conn.SetReadDeadline` not called
- No timeout on outbound HTTP: `http.Client{}` with no `Timeout` field set
- XML/JSON deeply nested structures causing stack overflow on recursive parsers

**Go-specific pitfalls:**
- `json.Decoder` by default reads the entire body into memory before decoding — always wrap with `http.MaxBytesReader`.
- `regexp.Compile(userInput)` is dangerous if the user can craft exponential-backtracking patterns; prefer fixed compiled regexes.
- Goroutine spawned per request with no limit (semaphore pattern missing).

---

## 11. Open Redirect

**Detection heuristics — search for:**
- `http.Redirect(w, r, userInput, http.StatusFound)` where `userInput` comes from a query parameter or form field
- `c.Redirect(http.StatusFound, userInput)` (Gin)
- `ctx.Redirect(userInput, http.StatusFound)` (Echo)
- Redirect targets built with `r.URL.Query().Get("next")` or `r.URL.Query().Get("redirect")`

**Safe patterns:**
- Validate that the redirect target is a relative path or belongs to an allowlist of trusted domains.
- Parse with `url.Parse` and check `u.Host == ""` for relative URLs.

---

## 12. CORS Misconfiguration

**Detection heuristics — search for:**
- `w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))` — reflects origin without validation
- `Access-Control-Allow-Origin: *` combined with `Access-Control-Allow-Credentials: true` — browsers block this, but check for auth bypass scenarios
- Wildcard allowed methods: `Access-Control-Allow-Methods: *`
- CORS middleware with `AllowAllOrigins: true` in sensitive APIs (Gin CORS, rs/cors)

---

## 13. Business Logic Vulnerabilities

These require understanding the application's intended behavior. Look for:

- **Negative values accepted in financial operations**: `amount` field not validated to be positive — negative transfer could credit funds.
- **Integer-based ID enumeration**: resource IDs are sequential integers with no ownership check.
- **State machine bypass**: order of operations not enforced — e.g., completing a checkout without paying.
- **Mass assignment**: `json.Unmarshal(body, &user)` where `user` is a full DB model struct (attacker sets `IsAdmin: true`).
- **Rate limiting absent on sensitive actions**: login, OTP verification, password reset, coupon redemption.
- **Time-of-check / time-of-use in transactions**: balance checked and deducted in separate non-atomic operations.

---

## 14. Dependency & Supply Chain Risks

**What to check in go.mod:**
- Dependencies with known CVEs — cross-reference by package name + major version:
  - `github.com/dgrijalva/jwt-go` — CVE-2020-26160 (algorithm confusion), replaced by `golang-jwt/jwt`
  - `github.com/gin-gonic/gin` < 1.9.0 — several path/MIME issues
  - `gopkg.in/yaml.v2` — use v3 where possible
  - `github.com/gorilla/websocket` — check for DoS if not rate-limited
- Unmaintained packages (no releases in 2+ years, open security issues)
- Direct use of `replace` directives pointing to local or forked paths
- Pinned vs. unpinned versions (use of pseudo-versions is fine; use of version ranges is unusual in Go and worth checking)

---

## 15. Error Handling & Information Leakage

**Detection heuristics — search for:**
- Returning raw `err.Error()` strings to HTTP clients: `c.JSON(500, err.Error())`
- Returning database errors verbatim: includes table names, column names, query structure
- Stack trace exposure: `debug.Stack()` or `runtime.Stack()` in error responses
- Default Go HTTP error handler exposing goroutine dumps on panic (use `recover()` middleware)
- Verbose 404/405 errors disclosing route structure

---

## 16. HTTP Security Headers

Check for missing headers on HTTP responses:

| Header | Purpose |
|---|---|
| `X-Content-Type-Options: nosniff` | Prevent MIME sniffing |
| `X-Frame-Options: DENY` | Clickjacking protection |
| `Content-Security-Policy` | XSS mitigation for web UIs |
| `Strict-Transport-Security` | Force HTTPS |
| `Referrer-Policy` | Limit referrer leakage |
| `Permissions-Policy` | Restrict browser features |

For pure API services (no HTML responses), CSP and X-Frame-Options are lower priority, but HSTS and X-Content-Type-Options still apply.

---

## 17. Integer Overflow & Type Confusion

**Detection heuristics — search for:**
- `int32` / `int16` / `uint8` used for values that can come from user input and be used in memory allocation or loop bounds
- Conversion from `int64` to `int32` without range check: `int32(userValue)`
- `strconv.Atoi` (returns `int`, platform-dependent size) used in 32-bit-unsafe contexts
- Multiplication without overflow check: `size * count` where both are user-controlled

**Go-specific:**
- On 64-bit platforms, `int` is 64-bit, so pure Go is less often vulnerable than C. But explicit narrowing casts are still dangerous.
- CGo interactions can introduce 32/64 bit mismatches.

---

## 18. Template Injection (SSTI)

**Detection heuristics — search for:**
- `html/template` or `text/template` with user-controlled template strings: `template.Must(template.New("").Parse(userInput))`
- `text/template` (not `html/template`) used for HTML output — lacks auto-escaping
- Template functions registered that perform dangerous operations (file access, exec)

**Go-specific:**
- `html/template` auto-escapes context-appropriately, so injecting `<script>` into a data value is safe. However, passing user input as the *template source* (not data) is always dangerous.
- `text/template` has no escaping — never use it for HTML responses.

---

## 19. Goroutine Leak & Resource Exhaustion

**Detection heuristics — search for:**
- `go func() { ... }()` inside a request handler without any backpressure mechanism (semaphore, worker pool, context cancellation)
- `time.After(d)` in a `select` inside a long-running loop — creates a new timer on every iteration; use `time.NewTimer` with `Reset`
- HTTP response body not closed after use: `resp.Body.Close()` missing
- Database connection not returned to pool: `defer rows.Close()` missing, `rows.Err()` not checked
- Context passed to goroutine not checked: `ctx.Done()` channel never read — goroutine outlives request

---

## 20. Unsafe Package Misuse

**Detection heuristics — search for:**
- `import "unsafe"` combined with pointer arithmetic
- `unsafe.Pointer` conversions between incompatible types
- `reflect.SliceHeader` / `reflect.StringHeader` manipulation (deprecated, use `unsafe.Slice` / `unsafe.SliceData` in Go 1.17+)
- `//go:linkname` directives accessing internal runtime symbols
- CGo with `C.free`, `C.malloc` and Go GC interaction issues

**When it's OK:** `unsafe` is legitimately used in zero-copy serialization and interop. Look for whether the invariants are documented and whether they hold across the codebase.
