# Go 安全规则参考

本参考包含审计 Go 代码时的完整漏洞模式检查表和检测启发式规则。每个章节对应一个漏洞类别。对于每个类别，检测启发式规则告诉你要搜索哪些代码模式，注释部分解释 Go 专项陷阱。

---

## 目录

1. [SQL 注入](#1-sql-注入)
2. [命令注入](#2-命令注入)
3. [服务端请求伪造（SSRF）](#3-服务端请求伪造ssrf)
4. [路径穿越 / 任意文件读写](#4-路径穿越--任意文件读写)
5. [认证与授权缺陷](#5-认证与授权缺陷)
6. [不安全反序列化](#6-不安全反序列化)
7. [敏感数据暴露](#7-敏感数据暴露)
8. [竞态条件与并发缺陷](#8-竞态条件与并发缺陷)
9. [密码学弱点](#9-密码学弱点)
10. [拒绝服务（DoS）](#10-拒绝服务dos)
11. [开放重定向](#11-开放重定向)
12. [CORS 配置错误](#12-cors-配置错误)
13. [业务逻辑漏洞](#13-业务逻辑漏洞)
14. [依赖与供应链风险](#14-依赖与供应链风险)
15. [错误处理与信息泄漏](#15-错误处理与信息泄漏)
16. [HTTP 安全响应头缺失](#16-http-安全响应头缺失)
17. [整数溢出与类型混淆](#17-整数溢出与类型混淆)
18. [模板注入（SSTI）](#18-模板注入ssti)
19. [Goroutine 泄漏与资源耗尽](#19-goroutine-泄漏与资源耗尽)
20. [unsafe 包滥用](#20-unsafe-包滥用)

---

## 1. SQL 注入

**检测启发式规则 — 搜索：**
- 字符串直接拼接进 SQL：`"SELECT" + `、`fmt.Sprintf("SELECT`、`fmt.Sprintf("INSERT`、`fmt.Sprintf("UPDATE`、`fmt.Sprintf("DELETE`
- 原始查询执行：`db.Query(`、`db.Exec(`、`db.QueryRow(`、`db.QueryContext(`、`db.ExecContext(`、`db.QueryRowContext(`
- GORM 原始 SQL：`.Raw(`、`.Exec(`、`.Where(fmt.Sprintf`
- sqlx：`db.Get(`、`db.Select(`、`db.NamedExec(`
- 任何变量拼接进字符串后传递给查询方法

**安全模式（对比参考）：**
- 参数化查询：`db.Query("SELECT * FROM t WHERE id = ?", id)`
- 命名参数：`db.NamedExec("INSERT INTO ... :name", map[string]interface{}{"name": name})`
- GORM ORM 方法：`.Where("id = ?", id).Find(&result)`

**Go 专项陷阱：**
- `fmt.Sprintf` 是 Go 中最常见的注入向量——它看起来无害，实则危险。
- GORM 的 `.Where(string)` 不带占位符时不安全；`.Where("name = ?", name)` 才是安全的。
- 通过 `strconv.Itoa` 将整数转为字符串后再拼接，若来源不可信仍存在注入风险。

---

## 2. 命令注入

**检测启发式规则 — 搜索：**
- `exec.Command(`、`exec.CommandContext(`
- `syscall.Exec(`、`syscall.ForkExec(`
- 导入 `os/exec` 并将用户控制的字符串作为参数
- Shell 调用：`exec.Command("sh", "-c", userInput)`、`exec.Command("bash", "-c", ...)`
- 脚本运行器：`exec.Command("python", userInput)`、`exec.Command("node", userInput)`

**安全模式：**
- 将各参数作为独立字符串传递给 `exec.Command`：`exec.Command("git", "clone", repoURL)` — 避免 Shell 解释。
- 调用 exec 前进行白名单验证。

**Go 专项陷阱：**
- `exec.Command("sh", "-c", input)` 对未经过滤的输入始终是危险的。
- 即使二进制文件名固定，攻击者控制的参数也可能在 `curl`、`tar`、`git`、`ffmpeg` 等工具中触发参数注入。
- 检查路径注入：`exec.Command(userControlledPath, ...)`。

---

## 3. 服务端请求伪造（SSRF）

**检测启发式规则 — 搜索：**
- `http.Get(`、`http.Post(`、`http.NewRequest(` 且 URL 部分或全部来自用户输入
- HTTP 客户端库：`resty.`、`fasthttp.`、`http.Client{}.Do(`
- 从用户输入构造 URL：`url.Parse(userInput)`、`fmt.Sprintf("http://"+host)`
- 使用用户控制地址的 gRPC 拨号：`grpc.Dial(userAddress, ...)`
- 任何用户提供主机名、IP 或完整 URL 后服务器再进行请求的代码路径

**安全模式：**
- 发起请求前对允许的域名/IP 进行白名单验证。
- 解析主机名后检查是否属于内网 IP 范围（127.0.0.0/8、169.254.0.0/16、10.0.0.0/8 等）。
- 使用屏蔽私有 IP 的自定义 `http.Transport`。

**Go 专项陷阱：**
- Go 的 `net/http` 默认跟随重定向——SSRF 可通过重定向到内网服务来升级危害。
- 云元数据端点（169.254.169.254）是 SSRF 的关键目标。
- DNS 重绑定：一个域名在检查时解析到公网 IP，但实际请求时解析到内网 IP。

---

## 4. 路径穿越 / 任意文件读写

**检测启发式规则 — 搜索：**
- `os.Open(`、`os.ReadFile(`、`ioutil.ReadFile(` 使用用户可控路径
- `filepath.Join(` 带用户可控组件——注意：若输入以 `/` 开头或包含 `..`，`filepath.Join` **不能**防止穿越
- `http.ServeFile(`、`http.FileServer(` 使用用户可控路径
- `os.Create(`、`os.WriteFile(`、`ioutil.WriteFile(` 使用用户可控路径
- 模板加载：`template.ParseFiles(userPath)`
- 解压存档时未验证路径：`zip.NewReader`、`tar.NewReader` 写入磁盘

**安全模式：**
- `filepath.Clean` + 断言结果具有预期前缀：`strings.HasPrefix(filepath.Clean(fullPath), allowedBase)`
- 拒绝包含 `..` 或绝对路径的输入。

**Go 专项陷阱：**
- `filepath.Join("/safe/base", "../../../etc/passwd")` 仍会解析为 `/etc/passwd`——`filepath.Join` 本身不是净化函数。
- Zip/tar 解压中的"Zip Slip"漏洞：存档条目名称中含 `../` 会覆盖任意文件。写入前始终调用 `filepath.Clean` 并验证最终路径。

---

## 5. 认证与授权缺陷

### 5a. JWT 漏洞

**检测启发式规则：**
- `jwt.Parse(` 未验证 `alg`——允许 `alg=none` 攻击
- `jwt.ParseWithClaims(` — 检查 `Keyfunc` 是否拒绝非预期算法
- 源码中硬编码密钥：`jwt.NewWithClaims(jwt.SigningMethodHS256, claims)` 使用字面量字符串密钥
- 弱密钥：长度短于 32 字节的密钥
- 解析后未检查过期时间声明

**Go 专项：**
- `golang-jwt/jwt` v4 及更早版本：`jwt.Parse` 的 `Keyfunc` 未检查 `token.Method` 即返回密钥，允许算法混淆攻击（例如 RS256 → HS256，将公钥作为 HMAC 密钥）。
- 始终断言：`if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok { return nil, fmt.Errorf("非预期的签名方法") }`

### 5b. 认证中间件缺失或被绕过

**检测启发式规则：**
- 路由组注册时未挂载认证中间件
- 中间件在路由注册*之后*添加（大多数 Go 路由框架中，顺序很重要）
- 认证失败时中间件仍调用 `next.ServeHTTP`（缺少 `return`）
- Gin/Echo 中间件中无论认证结果如何都调用 `c.Next()`

### 5c. 访问控制失效 / IDOR

**检测启发式规则：**
- 直接从请求中获取资源 ID 而未进行所有权检查：`r.URL.Query().Get("user_id")` 用于 DB 查询而未验证其是否属于当前认证用户
- 仅由前端检查保护的管理员操作，服务端无角色验证
- 水平越权：用户 A 能读写用户 B 的资源

### 5d. 硬编码凭证

**检测启发式规则：**
- `password =`、`secret =`、`apiKey =`、`token =`、`passwd =` 右侧为字符串字面量
- Basic Auth：`req.SetBasicAuth("admin", "password123")`
- 数据库 DSN 含明文密码：`"postgres://user:password@host/db"`

---

## 6. 不安全反序列化

**检测启发式规则 — 搜索：**
- 从不可信输入解码 `encoding/gob`：`gob.NewDecoder(r.Body).Decode(&obj)`
- `encoding/xml` 的 `xml.Unmarshal(data, &obj)` — Go 标准库中 XXE 不可利用，但第三方解析器中的外部实体解析可能存在 XXE
- `json.Unmarshal` 目标为 `interface{}`（任意类型实例化）
- `yaml.Unmarshal`（go-yaml v2）目标为 `interface{}` — go-yaml v2 会反序列化 `!!python/object` 标签并可调用 `Unmarshal` 方法；使用带严格类型目标的 `yaml.v3`
- `msgpack.Unmarshal` 使用多态类型
- `proto.Unmarshal` — 通常安全，但检查递归消息是否导致栈溢出

**Go 专项陷阱：**
- go-yaml v2 的 `Unmarshal` 目标为 `interface{}` 是经典攻击向量；go-yaml v3 更安全。
- 类型上的自定义 `UnmarshalJSON` / `UnmarshalBinary` 方法若执行副作用（如文件系统访问），可在反序列化时被触发。

---

## 7. 敏感数据暴露

**检测启发式规则 — 搜索：**
- 记录含敏感字段的日志：`log.Printf("user: %+v", user)` 且 user 结构体含 password/token 字段
- JSON 标签暴露内部字段：用于 HTTP 响应的结构体中有 `json:"password"`
- 向客户端返回含 SQL 查询、堆栈跟踪或内网 IP 的错误消息
- 明文存储密码或使用弱哈希算法（无盐 MD5、SHA1）
- 调试路径中的 `fmt.Println(password)` 或 `log.Println(secret)`
- URL 查询参数中的令牌（会进入日志）：`GET /api?token=xxx`

**安全模式：**
- 敏感字段使用 `json:"-"` 标签排除出 JSON 序列化。
- 使用 `bcrypt` / `argon2` 进行密码哈希。
- 日志脱敏：记录前对字段进行遮蔽处理。

---

## 8. 竞态条件与并发缺陷

**检测启发式规则 — 搜索：**
- 从 goroutine 访问共享可变状态（包级或结构体级变量）而未同步：
  - 在处理函数中修改全局 `var`
  - 多个 goroutine 读写 `map` 而未使用 `sync.RWMutex`
  - 并发 goroutine 执行 slice append
- `sync.WaitGroup` 误用：在 goroutine 内部而非 `go` 调用之前执行 `wg.Add`
- `sync.Mutex` 按值复制（应通过指针传递）
- goroutine 循环中的 `time.After` 导致 goroutine 泄漏和计时器 GC 压力
- 无 `select` + `default` 的 channel 操作可能无限阻塞（死锁风险）
- TOCTOU（检查时间/使用时间）：`os.Stat(path)` 后跟 `os.Open(path)` — 另一个 goroutine 可能在检查之间替换文件

**Go 专项陷阱：**
- map 并发使用不安全；使用 `sync.Map` 或互斥锁保护的 map。
- goroutine 中的闭包按引用捕获循环变量：`for _, v := range items { go func() { use(v) }() }` — `v` 是共享的。
- `http.Handler` 方法被并发调用；任何处理器级别的状态都必须是线程安全的。

---

## 9. 密码学弱点

**检测启发式规则 — 搜索：**
- 弱算法：`md5.New()`、`sha1.New()`、`des.NewCipher(`、`rc4.NewCipher(`
- ECB 模式：`cipher.NewCBCEncrypter` / `cipher.NewCBCDecrypter` — 非 ECB 本身，但检查无 HMAC 的 CBC（填充预言攻击）
- 静态/硬编码 IV 或 nonce：`iv := []byte("0000000000000000")`
- 将 `math/rand` 用于安全敏感操作（令牌生成、nonce、OTP）：来自 `math/rand`（非 `crypto/rand`）的 `rand.Intn(`、`rand.Read(`
- RSA 加密未使用 OAEP：`rsa.EncryptPKCS1v15(`
- TLS 配置含 `InsecureSkipVerify: true`
- TLS 最低版本低于 1.2：`MinVersion: tls.VersionTLS10`
- 弱密钥长度：RSA < 2048 位，ECDSA 使用 P-224

**安全替代方案：**
- 使用 `crypto/rand` 生成随机字节；以 `rand.Reader` 作为熵源。
- 使用 AES-GCM 进行认证加密。
- 密码使用 `argon2id` 或 `bcrypt`。
- 哈希使用 `sha256` / `sha3`。

---

## 10. 拒绝服务（DoS）

**检测启发式规则 — 搜索：**
- 缺少请求体大小限制：`json.NewDecoder(r.Body).Decode(&v)` 未包装 `http.MaxBytesReader`
- 对用户输入执行无界正则：`regexp.MustCompile(userPattern)`（ReDoS）
- 用户控制值驱动的无界循环：`for i := 0; i < userCount; i++`
- 无界内存分配：`make([]byte, userSize)`
- 连接无读取截止时间：未调用 `conn.SetReadDeadline`
- 出站 HTTP 无超时：`http.Client{}` 未设置 `Timeout` 字段
- XML/JSON 深度嵌套结构在递归解析器中导致栈溢出

**Go 专项陷阱：**
- `json.Decoder` 默认在解码前将整个 body 读入内存——始终使用 `http.MaxBytesReader` 包装。
- 若用户能构造指数级回溯模式，`regexp.Compile(userInput)` 是危险的；优先使用预编译的固定正则。
- 每个请求生成一个 goroutine 而无数量限制（缺少信号量模式）。

---

## 11. 开放重定向

**检测启发式规则 — 搜索：**
- `http.Redirect(w, r, userInput, http.StatusFound)` 其中 `userInput` 来自查询参数或表单字段
- `c.Redirect(http.StatusFound, userInput)`（Gin）
- `ctx.Redirect(userInput, http.StatusFound)`（Echo）
- 使用 `r.URL.Query().Get("next")` 或 `r.URL.Query().Get("redirect")` 构建重定向目标

**安全模式：**
- 验证重定向目标是相对路径或属于可信域名白名单。
- 使用 `url.Parse` 解析并检查 `u.Host == ""`（相对 URL）。

---

## 12. CORS 配置错误

**检测启发式规则 — 搜索：**
- `w.Header().Set("Access-Control-Allow-Origin", r.Header.Get("Origin"))` — 未经验证地反射来源
- `Access-Control-Allow-Origin: *` 与 `Access-Control-Allow-Credentials: true` 同时使用 — 浏览器会阻止此组合，但检查认证绕过场景
- 通配符允许方法：`Access-Control-Allow-Methods: *`
- 敏感 API 中 CORS 中间件使用 `AllowAllOrigins: true`（Gin CORS、rs/cors）

---

## 13. 业务逻辑漏洞

这些漏洞需要理解应用程序的预期行为。关注：

- **财务操作中接受负值**：`amount` 字段未验证为正数——负数转账可能造成余额增加。
- **基于整数的 ID 枚举**：资源 ID 为连续整数且无所有权检查。
- **状态机绕过**：未强制执行操作顺序——例如未支付即完成结账。
- **批量赋值**：`json.Unmarshal(body, &user)` 其中 `user` 是完整的 DB 模型结构体（攻击者设置 `IsAdmin: true`）。
- **敏感操作缺少频率限制**：登录、OTP 验证、密码重置、优惠券兑换。
- **事务中的检查时间/使用时间**：余额检查和扣除在非原子操作中分开执行。

---

## 14. 依赖与供应链风险

**在 go.mod 中检查：**
- 已知 CVE 的依赖——按包名 + 主版本号交叉对照：
  - `github.com/dgrijalva/jwt-go` — CVE-2020-26160（算法混淆），已被 `golang-jwt/jwt` 替代
  - `github.com/gin-gonic/gin` < 1.9.0 — 若干路径/MIME 问题
  - `gopkg.in/yaml.v2` — 尽可能使用 v3
  - `github.com/gorilla/websocket` — 若无频率限制检查 DoS 风险
- 无维护的包（2 年以上无发布、有未解决安全问题）
- 直接使用指向本地或 fork 路径的 `replace` 指令
- 固定版本与非固定版本（使用伪版本号没问题；Go 中使用版本范围不常见，值得检查）

---

## 15. 错误处理与信息泄漏

**检测启发式规则 — 搜索：**
- 向 HTTP 客户端返回原始 `err.Error()` 字符串：`c.JSON(500, err.Error())`
- 原样返回数据库错误：包含表名、列名、查询结构
- 堆栈跟踪暴露：错误响应中有 `debug.Stack()` 或 `runtime.Stack()`
- 默认 Go HTTP 错误处理器在 panic 时暴露 goroutine 转储（使用 `recover()` 中间件）
- 冗长的 404/405 错误泄露路由结构

---

## 16. HTTP 安全响应头缺失

检查 HTTP 响应中缺少的头：

| 响应头 | 用途 |
|---|---|
| `X-Content-Type-Options: nosniff` | 防止 MIME 嗅探 |
| `X-Frame-Options: DENY` | 防止点击劫持 |
| `Content-Security-Policy` | Web UI 的 XSS 缓解 |
| `Strict-Transport-Security` | 强制 HTTPS |
| `Referrer-Policy` | 限制 Referer 泄漏 |
| `Permissions-Policy` | 限制浏览器特性 |

对于纯 API 服务（无 HTML 响应），CSP 和 X-Frame-Options 优先级较低，但 HSTS 和 X-Content-Type-Options 仍适用。

---

## 17. 整数溢出与类型混淆

**检测启发式规则 — 搜索：**
- `int32` / `int16` / `uint8` 用于可来自用户输入且用于内存分配或循环边界的值
- 从 `int64` 到 `int32` 的无范围检查转换：`int32(userValue)`
- `strconv.Atoi`（返回平台相关大小的 `int`）在 32 位不安全场景中使用
- 无溢出检查的乘法：`size * count` 两者均用户可控

**Go 专项：**
- 在 64 位平台上，`int` 是 64 位，纯 Go 代码比 C 更少出现此类漏洞。但显式窄化转型仍然危险。
- CGo 交互可能引入 32/64 位不匹配。

---

## 18. 模板注入（SSTI）

**检测启发式规则 — 搜索：**
- `html/template` 或 `text/template` 使用用户控制的模板字符串：`template.Must(template.New("").Parse(userInput))`
- `text/template`（非 `html/template`）用于 HTML 输出——缺少自动转义
- 注册了执行危险操作（文件访问、exec）的模板函数

**Go 专项：**
- `html/template` 会根据上下文自动转义，因此将 `<script>` 注入数据值是安全的。但将用户输入作为*模板源*（而非数据）始终是危险的。
- `text/template` 没有转义——永远不要将其用于 HTML 响应。

---

## 19. Goroutine 泄漏与资源耗尽

**检测启发式规则 — 搜索：**
- 请求处理器中的 `go func() { ... }()` 没有任何背压机制（信号量、工作池、context 取消）
- 长时间运行循环中 `select` 内的 `time.After(d)` — 每次迭代创建新计时器；使用 `time.NewTimer` 和 `Reset`
- HTTP 响应体使用后未关闭：缺少 `resp.Body.Close()`
- 数据库连接未归还连接池：缺少 `defer rows.Close()`，未检查 `rows.Err()`
- 传递给 goroutine 的 context 未被检查：从未读取 `ctx.Done()` channel——goroutine 生命周期超过请求

---

## 20. unsafe 包滥用

**检测启发式规则 — 搜索：**
- `import "unsafe"` 结合指针运算
- `unsafe.Pointer` 在不兼容类型之间的转换
- `reflect.SliceHeader` / `reflect.StringHeader` 操作（已废弃，Go 1.17+ 中使用 `unsafe.Slice` / `unsafe.SliceData`）
- `//go:linkname` 指令访问运行时内部符号
- CGo 中 `C.free`、`C.malloc` 与 Go GC 交互问题

**何时可以接受：** `unsafe` 在零拷贝序列化和互操作中有合理用途。检查其不变式是否有文档记录，以及这些不变式是否在整个代码库中成立。
