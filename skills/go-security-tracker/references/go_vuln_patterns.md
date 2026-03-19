# Go 语言漏洞特征模式库

本文档总结业界著名 Go 开源项目中高频出现的安全漏洞特征，每种模式附有真实案例、代码示例和检测要点，供安全 review 使用。

## 目录

- [G-DOS: 拒绝服务](#g-dos-拒绝服务)
- [G-AUTH: 认证/授权绕过](#g-auth-认证授权绕过)
- [G-PATH: 路径遍历](#g-path-路径遍历)
- [G-PROTO: 序列化漏洞](#g-proto-序列化漏洞)
- [G-INJ: 注入类漏洞](#g-inj-注入类漏洞)
- [G-SSRF: 服务端请求伪造](#g-ssrf-服务端请求伪造)
- [G-CRYPTO: 密码学问题](#g-crypto-密码学问题)
- [G-RACE: 竞争条件](#g-race-竞争条件)
- [G-MEM: 内存安全](#g-mem-内存安全)
- [G-SUPPLY: 供应链安全](#g-supply-供应链安全)
- [检测工具速查](#检测工具速查)

---

## G-DOS: 拒绝服务

### 模式 1: HTTP/2 流重置攻击 (CVE-2023-44487 "Rapid Reset")

**受影响项目**: net/http, grpc-go, nghttp2  
**严重度**: HIGH

**特征**: 攻击者快速发送大量 HTTP/2 RST_STREAM 帧，服务端无法限制并发流，导致 CPU 耗尽。

```go
// 漏洞代码模式（net/http < 1.21.3）
// 未对 HTTP/2 MaxConcurrentStreams 和重置率设置限制

// 修复方式
import "golang.org/x/net/http2"

s := &http2.Server{
    MaxConcurrentStreams: 250,       // 限制并发流
    MaxReadFrameSize:     1 << 20,   // 限制帧大小
}
```

**检测要点**:
- `grep -r "http2.Server{" .` 检查是否设置了 `MaxConcurrentStreams`
- `grep -r "net/http"` 检查 Go 版本是否 >= 1.21.3

---

### 模式 2: 正则表达式回溯 (ReDoS)

**受影响项目**: traefik (CVE-2022-23469), go-jose  
**严重度**: HIGH

**特征**: 用户可控的正则表达式输入触发指数级回溯，导致 CPU 100% 占用。

```go
// 漏洞代码模式
pattern := req.Header.Get("X-Route-Pattern")  // 用户输入
matched, _ := regexp.MatchString(pattern, path)  // 危险！

// 修复方式
// 1. 不允许用户控制正则表达式
// 2. 设置超时上下文
import "context"
ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
defer cancel()
// regexp 包不支持 context，改用 github.com/dlclark/regexp2

// 3. 使用 regexp/syntax 预检查是否存在回溯风险
```

**检测要点**:
- 搜索 `regexp.MatchString` / `regexp.Compile` 附近是否有用户输入

---

### 模式 3: goroutine 泄漏导致内存耗尽

**受影响项目**: kubernetes, prometheus  
**严重度**: MEDIUM

**特征**: goroutine 在 channel 阻塞或 context 未正确传播，导致 goroutine 数量无限增长。

```go
// 漏洞代码模式
func handleRequest(req *http.Request) {
    ch := make(chan Result)
    go func() {
        // 如果 HTTP 请求中断，调用方不再读取 ch，goroutine 永远阻塞
        ch <- compute(req)
    }()
    select {
    case result := <-ch:
        // ...
    case <-time.After(5 * time.Second):
        return  // goroutine 泄漏！
    }
}

// 修复方式：使用带缓冲 channel 或传播 context
func handleRequest(ctx context.Context, req *http.Request) {
    ch := make(chan Result, 1)  // 缓冲 channel 防止 goroutine 阻塞
    go func() {
        select {
        case ch <- compute(ctx, req):
        case <-ctx.Done():  // context 取消时退出
        }
    }()
}
```

**检测要点**:
- 审查无缓冲 channel 的 `go func()` 使用
- 使用 `github.com/uber-go/goleak` 进行测试

---

### 模式 4: 请求体大小无限制

**受影响项目**: 几乎所有 Go HTTP 服务  
**严重度**: MEDIUM

```go
// 漏洞代码模式
body, err := io.ReadAll(r.Body)  // 读取无限大小的请求体

// 修复方式
r.Body = http.MaxBytesReader(w, r.Body, 10*1024*1024)  // 限制 10MB
body, err := io.ReadAll(r.Body)
if err != nil {
    if errors.Is(err, &http.MaxBytesError{}) {
        http.Error(w, "request too large", http.StatusRequestEntityTooLarge)
        return
    }
}
```

---

## G-AUTH: 认证/授权绕过

### 模式 1: JWT alg:none 攻击

**受影响项目**: go-jose (CVE-2023-48795), dgrijalva/jwt-go  
**严重度**: CRITICAL

**特征**: JWT 库不强制验证算法类型，攻击者可将 `alg` 设为 `none` 绕过签名验证。

```go
// 漏洞代码模式（旧版 jwt-go）
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    return secretKey, nil  // 未检查算法类型！
})

// 修复方式
token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
    // 强制验证算法
    if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
        return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
    }
    return secretKey, nil
})
```

**检测要点**:
- `grep -r "jwt.Parse" .` 检查是否验证 `token.Method`

---

### 模式 2: Kubernetes RBAC 绕过（CVE-2019-11253）

**受影响项目**: kubernetes/kubernetes  
**严重度**: HIGH

**特征**: YAML/JSON 解析器允许特殊字段导致 RBAC 策略评估逻辑被绕过。

**检测要点**:
- 使用 `kube-bench` 定期检查 RBAC 配置
- 限制对 API server 的 `create`/`update`/`patch` 权限

---

### 模式 3: 中间件顺序导致认证绕过

**受影响项目**: traefik, gin  
**严重度**: HIGH

**特征**: 认证中间件未在路由处理前执行，某些路径可绕过认证。

```go
// 漏洞代码模式
r := gin.New()
r.GET("/api/data", authMiddleware(), dataHandler)  // 仅特定路由有认证
r.GET("/api/export", dataHandler)  // 忘记添加认证！

// 修复方式：全局应用认证中间件
authGroup := r.Group("/api", authMiddleware())
authGroup.GET("/data", dataHandler)
authGroup.GET("/export", dataHandler)
```

---

### 模式 4: 时间侧信道攻击

**受影响项目**: hashicorp/vault  
**严重度**: MEDIUM

```go
// 漏洞代码模式
if storedToken == providedToken {  // 可能存在时序侧信道
    // ...
}

// 修复方式
import "crypto/subtle"
if subtle.ConstantTimeCompare([]byte(storedToken), []byte(providedToken)) == 1 {
    // ...
}
```

---

## G-PATH: 路径遍历

### 模式 1: filepath.Join 绕过 (CVE-2023-29403)

**受影响项目**: containerd/containerd, runc  
**严重度**: HIGH

**特征**: `filepath.Join` 会清理路径但不阻止绝对路径覆盖，攻击者可使用绝对路径逃逸。

```go
// 漏洞代码模式
func serveFile(baseDir, userPath string) {
    // filepath.Join("/var/www", "/etc/passwd") = "/etc/passwd" ← 危险！
    fullPath := filepath.Join(baseDir, userPath)
    http.ServeFile(w, r, fullPath)
}

// 修复方式
func serveFile(baseDir, userPath string) error {
    cleanPath := filepath.Clean(userPath)
    if strings.HasPrefix(cleanPath, "..") {
        return errors.New("invalid path: path traversal detected")
    }
    fullPath := filepath.Join(baseDir, cleanPath)
    // 额外验证：确保 fullPath 在 baseDir 内
    rel, err := filepath.Rel(baseDir, fullPath)
    if err != nil || strings.HasPrefix(rel, "..") {
        return errors.New("invalid path: outside base directory")
    }
    http.ServeFile(w, r, fullPath)
    return nil
}
```

**检测要点**:
- `grep -rn "filepath.Join" .` 检查入参是否来自用户输入

---

### 模式 2: 符号链接攻击

**受影响项目**: containerd (CVE-2022-23648)  
**严重度**: HIGH

**特征**: 容器镜像中包含符号链接指向宿主机路径，在 extract 时跟随符号链接写入宿主机文件。

```go
// 漏洞代码模式
// 解压 tar 时未验证符号链接目标
for _, header := range tarHeaders {
    if header.Typeflag == tar.TypeSymlink {
        os.Symlink(header.Linkname, header.Name)  // 危险！Linkname 可指向 /etc/
    }
}

// 修复方式：验证符号链接目标
func validateSymlink(base, name, target string) error {
    // 规范化路径并确保在 base 目录内
    absTarget := filepath.Join(base, target)
    rel, err := filepath.Rel(base, absTarget)
    if err != nil || strings.HasPrefix(rel, "..") {
        return fmt.Errorf("symlink target escapes base dir: %s -> %s", name, target)
    }
    return nil
}
```

---

## G-PROTO: 序列化漏洞

### 模式 1: YAML 任意代码执行 (go-yaml v2)

**受影响项目**: kubernetes (历史), helm  
**严重度**: CRITICAL

**特征**: `gopkg.in/yaml.v2` 的某些版本在解析时可执行任意 Go 类型构造，类似 Python pickle。

```go
// 漏洞代码模式（yaml.v2 某些版本）
var result interface{}
yaml.Unmarshal(untrustedData, &result)  // 危险！

// 修复方式：使用严格类型，升级到 yaml.v3，并禁用危险标签
import "gopkg.in/yaml.v3"

var config MyConfig  // 明确类型，不使用 interface{}
decoder := yaml.NewDecoder(bytes.NewReader(data))
decoder.KnownFields(true)  // 拒绝未知字段
err := decoder.Decode(&config)
```

---

### 模式 2: Protobuf 消息炸弹

**受影响项目**: grpc-go, kubernetes API  
**严重度**: HIGH

**特征**: Protobuf 支持嵌套消息，精心构造的小消息解码后占用大量内存（递归嵌套放大攻击）。

```go
// 修复方式：设置消息大小限制
import "google.golang.org/grpc"

conn, err := grpc.Dial(address,
    grpc.WithDefaultCallOptions(
        grpc.MaxCallRecvMsgSize(4*1024*1024),  // 限制接收 4MB
    ),
)

// 服务端限制
s := grpc.NewServer(
    grpc.MaxRecvMsgSize(4*1024*1024),
    grpc.MaxSendMsgSize(4*1024*1024),
)
```

---

### 模式 3: JSON 数字解析精度丢失

**受影响项目**: 含大整数 ID 的 API  
**严重度**: LOW

```go
// 漏洞代码模式
var data map[string]interface{}
json.Unmarshal(input, &data)
// data["id"] 会被解析为 float64，大整数精度丢失

// 修复方式
import "encoding/json"

decoder := json.NewDecoder(strings.NewReader(input))
decoder.UseNumber()  // 使用 json.Number 类型保留精度
```

---

## G-INJ: 注入类漏洞

### 模式 1: Go 模板注入 (text/template vs html/template)

**受影响项目**: grafana (历史), argo-cd  
**严重度**: HIGH

```go
// 漏洞代码模式
import "text/template"  // 危险！不进行 HTML 转义

tmpl := template.Must(template.New("").Parse(userInput))  // 更危险：用户输入作模板
tmpl.Execute(w, data)

// 修复方式：输出 HTML 时使用 html/template
import "html/template"

// 固定模板，用户输入只作为数据
const tmpl = `<h1>Hello, {{.Name}}</h1>`
t := template.Must(template.New("").Parse(tmpl))
t.Execute(w, struct{ Name string }{Name: userInput})  // 自动转义
```

**检测要点**:
- `grep -rn '"text/template"' .` 检查是否在 HTTP handler 中使用

---

### 模式 2: 命令注入

**受影响项目**: gitea (历史), 含 git 操作的服务  
**严重度**: CRITICAL

```go
// 漏洞代码模式
cmd := exec.Command("sh", "-c", "git clone " + userInput)  // 命令注入！

// 修复方式：使用参数数组，避免 shell 解析
cmd := exec.Command("git", "clone", "--", userInput)  // 安全：参数独立传递
cmd.Dir = safeDir

// 更彻底的方式：使用 go-git 库替代系统命令
import "github.com/go-git/go-git/v5"
_, err := git.PlainClone(targetDir, false, &git.CloneOptions{URL: validatedURL})
```

---

## G-SSRF: 服务端请求伪造

### 模式 1: http.Client 内网探测

**受影响项目**: argo-cd (CVE-2022-24348), 含 webhook/import 功能的服务  
**严重度**: HIGH

```go
// 漏洞代码模式
resp, err := http.Get(userProvidedURL)  // 可访问 169.254.169.254（云元数据）

// 修复方式：自定义 Transport 过滤内网地址
import "net"

func newSafeHTTPClient() *http.Client {
    return &http.Client{
        Transport: &http.Transport{
            DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
                host, port, err := net.SplitHostPort(addr)
                if err != nil {
                    return nil, err
                }
                ips, err := net.LookupHost(host)
                if err != nil {
                    return nil, err
                }
                for _, ip := range ips {
                    if isPrivateIP(net.ParseIP(ip)) {
                        return nil, fmt.Errorf("SSRF: private IP %s blocked", ip)
                    }
                }
                return net.Dial(network, net.JoinHostPort(ips[0], port))
            },
        },
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse  // 不自动跟随重定向
        },
        Timeout: 10 * time.Second,
    }
}

func isPrivateIP(ip net.IP) bool {
    privateRanges := []string{
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
        "127.0.0.0/8", "169.254.0.0/16",  // 云元数据服务
        "::1/128", "fc00::/7",
    }
    for _, cidr := range privateRanges {
        _, network, _ := net.ParseCIDR(cidr)
        if network.Contains(ip) {
            return true
        }
    }
    return false
}
```

---

## G-CRYPTO: 密码学问题

### 模式 1: math/rand 用于安全场景

```go
// 漏洞代码模式
import "math/rand"
token := fmt.Sprintf("%d", rand.Int63())  // 可预测！

// 修复方式
import (
    "crypto/rand"
    "encoding/hex"
)
b := make([]byte, 32)
rand.Read(b)
token := hex.EncodeToString(b)
```

### 模式 2: TLS 配置不安全

```go
// 漏洞代码模式
tlsConfig := &tls.Config{
    InsecureSkipVerify: true,  // 禁用证书验证！生产中严禁
    MinVersion: tls.VersionTLS10,  // 允许 TLS 1.0！
}

// 修复方式
tlsConfig := &tls.Config{
    MinVersion:               tls.VersionTLS12,
    PreferServerCipherSuites: true,
    CipherSuites: []uint16{
        tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
    },
}
```

---

## G-RACE: 竞争条件

### 模式 1: map 并发读写

```go
// 漏洞代码模式（map 并发写会 panic）
var cache = map[string]string{}  // 全局 map

func setCache(k, v string) {
    cache[k] = v  // 并发写 → panic: concurrent map writes
}

// 修复方式 1：sync.RWMutex
var (
    cache   = map[string]string{}
    cacheMu sync.RWMutex
)
func setCache(k, v string) {
    cacheMu.Lock()
    defer cacheMu.Unlock()
    cache[k] = v
}

// 修复方式 2：sync.Map
var cache sync.Map
cache.Store(k, v)
v, ok := cache.Load(k)
```

---

## G-MEM: 内存安全

### 模式 1: unsafe.Pointer 滥用

```go
// 危险的 unsafe 使用
func readInt(b []byte) int64 {
    return *(*int64)(unsafe.Pointer(&b[0]))  // 未检查边界！
}

// 安全方式
import "encoding/binary"
func readInt(b []byte) (int64, error) {
    if len(b) < 8 {
        return 0, errors.New("buffer too short")
    }
    return int64(binary.LittleEndian.Uint64(b)), nil
}
```

---

## G-SUPPLY: 供应链安全

### 模式 1: Go 模块替换攻击

```go
// 风险：go.mod 中的 replace 指令可指向恶意本地路径
replace github.com/legit/pkg => ../malicious-pkg

// 检测：在 CI 中验证 go.mod 中没有非预期的 replace 指令
// grep -n "^replace" go.mod | grep -v "github.com/yourorg"
```

### 模式 2: 依赖版本固定缺失

```bash
# 检测未固定依赖（使用通配符版本）
grep -n "latest\|master" go.mod

# 使用 govulncheck 扫描已知漏洞
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

---

## 检测工具速查

| 工具 | 安装 | 主要用途 |
|------|------|---------|
| `govulncheck` | `go install golang.org/x/vuln/cmd/govulncheck@latest` | 检查已知 CVE 漏洞 |
| `gosec` | `go install github.com/securego/gosec/v2/cmd/gosec@latest` | 静态安全扫描（100+ 规则）|
| `staticcheck` | `go install honnef.co/go/tools/cmd/staticcheck@latest` | 静态分析（含安全相关）|
| `go-race` | `go test -race ./...` | 竞争条件检测 |
| `golangci-lint` | `brew install golangci-lint` | 聚合多个 linter |
| `trivy` | `brew install trivy` | 容器/依赖漏洞扫描 |
| `nancy` | `go install github.com/sonatype-nexus-community/nancy@latest` | OSS Index 漏洞检查 |

### CI 配置示例 (GitHub Actions)

```yaml
- name: Run govulncheck
  run: |
    go install golang.org/x/vuln/cmd/govulncheck@latest
    govulncheck ./...

- name: Run gosec
  uses: securego/gosec@master
  with:
    args: '-severity medium -confidence medium ./...'

- name: Run tests with race detector
  run: go test -race -timeout 300s ./...
```
