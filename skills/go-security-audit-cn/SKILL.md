---
name: go-security-audit-cn
description: 对 Golang 项目进行全面的代码安全审计。当用户想要审计 Go 代码中的漏洞、在 Go 代码库中发现安全问题、根据安全最佳实践审查 Go 代码、识别 Go 服务的攻击面、检查 SQL 注入 / SSRF / 命令注入 / 认证绕过 / 竞态条件、生成 CVE 风格的安全漏洞报告，或进行 Go 安全代码审查时，使用此技能。即使用户只是说"帮我检查 Go 代码有没有安全问题"、"审计这个 Go 项目"或"找出这个 Go 服务的漏洞"，也应触发此技能。
---

# Go 代码安全审计

本技能用于对 Golang 项目执行深度、结构化的安全审计。审计遵循四阶段方法论：**项目侦察** → **攻击面梳理** → **代码级漏洞分析** → **漏洞报告输出**，最终生成包含完整漏洞详情的结构化报告。

---

## 环境说明与工具准备

> **在开始审计前，先完成本节的环境检查。** 技能的核心审计（手动代码阅读与分析）在任何环境中均可运行，无需网络连接。辅助扫描工具可选，若不可用会自动跳过。

本技能可调用三个辅助静态分析工具，作为手动审计的补充：

| 工具 | 用途 | 是否必须 |
|---|---|---|
| `govulncheck` | 扫描 go.mod 依赖中的已知 CVE | 可选 |
| `gosec` | Go 代码 SAST，自动检测常见安全模式 | 可选 |
| `staticcheck` | Go 静态分析，含安全相关检查 | 可选 |

### 环境检测

在开始审计前，运行以下命令检测工具可用性：

```bash
command -v govulncheck && govulncheck --version || echo "[未安装] govulncheck"
command -v gosec       && gosec --version       || echo "[未安装] gosec"
command -v staticcheck && staticcheck --version  || echo "[未安装] staticcheck"
```

### 有网络访问时：一键安装

```bash
bash skills/go-security-audit-cn/scripts/install_tools.sh
```

### 离线环境：预先准备工具

若目标机器无法访问公网，在**有网的机器**上预先编译，然后传输二进制文件到目标机器：

```bash
# 在联网机器上编译（需与目标机器同架构、同 OS）
GOBIN=/tmp/audit-tools go install golang.org/x/vuln/cmd/govulncheck@latest
GOBIN=/tmp/audit-tools go install github.com/securego/gosec/v2/cmd/gosec@latest
GOBIN=/tmp/audit-tools go install honnef.co/go/tools/cmd/staticcheck@latest

# 打包传输
tar -czf audit-tools.tar.gz -C /tmp audit-tools

# 在目标机器上安装
tar -xzf audit-tools.tar.gz
sudo cp audit-tools/* /usr/local/bin/ && chmod +x /usr/local/bin/govulncheck /usr/local/bin/gosec /usr/local/bin/staticcheck
```

> 详细的离线安装方案（含 Docker 镜像、内网 GOPROXY 代理、govulncheck 本地漏洞数据库配置）参见 `references/offline-setup.md`。

### 工具不可用时的行为

若工具均无法安装，**技能仍会完整运行**——所有四个阶段照常执行，依靠手动代码阅读与模式匹配完成审计。报告末尾会注明哪些辅助工具未运行，建议在有条件时补充执行。

---

## 第一阶段 — 项目侦察

在查找漏洞之前，先全面理解被审计的项目。

### 1.1 框架与依赖分析

- 读取 `go.mod` 和 `go.sum`，识别：
  - Web 框架（net/http、Gin、Echo、Fiber、Chi、Gorilla、gRPC 等）
  - ORM / 数据库驱动（GORM、sqlx、database/sql、mongo-driver、redis 等）
  - 认证库（jwt-go、golang-jwt、oauth2、casbin 等）
  - 加密库（bcrypt、x/crypto 等）
  - 外部 HTTP 客户端（resty、fasthttp 等）
  - 配置 / 密钥加载器（viper、envconfig、godotenv 等）
- 记录已知存在 CVE 的依赖（按包名和主版本号对照 GHSA / NVD 命名规范）
- 若 `govulncheck` 可用，运行它作为依赖漏洞扫描的第一步：
  ```bash
  govulncheck ./...
  ```

### 1.2 项目结构分析

- 梳理目录树：`cmd/`、`internal/`、`pkg/`、`api/`、`handler/`、`middleware/`、`model/`、`repository/`、`service/`、`config/` 等
- 识别入口点：`main.go`、CLI 命令、HTTP 服务启动、gRPC 服务注册
- 识别配置与密钥处理方式：环境变量、配置文件、Vault / AWS Secrets Manager 集成

### 1.3 编写侦察摘要

撰写 10–20 行的简短摘要，涵盖：
- 应用类型（REST API、gRPC 服务、CLI、Worker 等）
- 技术栈与关键依赖
- 部署环境线索（Dockerfile、k8s 清单、CI 配置）
- Go 代码行数（根据文件数量 × 平均行数粗估）

---

## 第二阶段 — 攻击面梳理

识别所有**不可信输入进入系统**的位置，以及所有**特权操作**所在的位置。

### 需要检查的入口点

| 入口点类型 | 关注内容 |
|---|---|
| HTTP 处理器 | 路由注册、请求体解析、URL 参数、请求头、Cookie |
| WebSocket 处理器 | 升级逻辑、消息解析 |
| gRPC 方法 | 一元与流式处理器、元数据提取 |
| CLI 参数 | `os.Args`、flag 解析、子命令分发 |
| 文件摄入 | 上传处理器、文件路径构造 |
| 消息队列 | Kafka/RabbitMQ/NATS 消费者、SQS 处理器 |
| 定时任务 / Cron | 触发输入、任务参数 |
| 环境变量 / 配置 | 从环境或配置文件读取并用于敏感操作的值 |

### 需要标记的高风险模块

列出以下类型的模块（文件或包）：
- 执行操作系统命令（`exec.Command`、`syscall.Exec`）
- 构造 SQL 查询（尤其是字符串拼接方式）
- 基于用户输入发起出站 HTTP/TCP 调用
- 处理认证 / 鉴权令牌
- 使用用户可控路径执行文件 I/O
- 反序列化不可信数据（JSON、XML、gob、带动态类型的 protobuf）
- 管理跨请求共享的 goroutine / channel（并发状态）

读取 `references/go-security-rules.md` 获取每个类别中需要查找的漏洞模式完整检查表。

---

## 第三阶段 — 代码级漏洞分析

系统性地审计代码。针对第二阶段识别出的每个高风险模块和入口点，追踪从输入到敏感操作的数据流。

### 辅助工具扫描（若可用）

若工具已安装，在手动审计前先运行，收集初步结果作为参考线索：

```bash
# SAST 扫描（输出到文件便于引用）
gosec -fmt=json -out=gosec-results.json ./... 2>/dev/null || gosec ./...

# 静态分析
staticcheck ./...

# 竞态检测（需要能编译和运行测试）
go test -race ./... 2>&1 | grep -E "DATA RACE|FAIL|ok"
```

扫描结果作为**辅助参考**，不能替代手动审计——SAST 工具有误报，也有漏报。对每个工具报告的问题，手动确认其是否真实可利用。

### 手动代码审计

逐一检查 `references/go-security-rules.md` 中列出的每个漏洞类别，对每个类别，搜索其中描述的具体 Go 代码模式。广泛使用代码搜索工具（Grep、Glob）——不要只是浏览。

### 追踪调用链

对每个发现，从入口点到漏洞代码位置重建**完整调用链**：

```
HTTP POST /api/v1/users
  → handler.CreateUser()            [handlers/user.go:42]
    → service.UserService.Create()  [service/user.go:88]
      → repo.UserRepo.Insert()      [repository/user.go:31]
        → db.QueryContext(ctx, "INSERT INTO users WHERE id="+id)  ← 漏洞点
```

同样要追踪中间件——缺失的认证中间件本身就是一个发现。

### 严重程度评级

| 严重程度 | 判定标准 |
|---|---|
| 严重（Critical） | 直接 RCE、认证绕过、明文凭证暴露 |
| 高危（High） | SQL 注入、SSRF、路径穿越、访问控制失效、不安全反序列化 |
| 中危（Medium） | 无影响放大的 IDOR、弱加密算法、敏感端点缺少频率限制、内部信息通过错误消息泄漏 |
| 低危（Low） | 时序侧信道、日志中不必要的数据暴露、缺少安全响应头 |
| 信息（Informational） | 安全影响较小的代码风格问题、无已知漏洞的过时依赖 |

---

## 第四阶段 — 漏洞报告

读取 `references/report-template.md` 获取报告的精确结构。

报告中每个发现**必须**包含：

1. **漏洞名称** — 清晰、描述性的标题（例如："用户搜索端点 SQL 注入"）
2. **严重程度** — 严重 / 高危 / 中危 / 低危 / 信息
3. **漏洞代码片段** — 精确的文件路径和行号，以及相关代码块
4. **调用链** — 从入口点到漏洞行的完整路径
5. **漏洞根因** — 一段话解释代码*为何*存在漏洞（不只是描述*做了什么*）
6. **漏洞验证（PoC）** — 证明可利用性的具体利用载荷或请求；对于不可直接利用的问题（如缺少响应头），描述攻击场景
7. **修复建议** — 修复该问题的具体 Go 代码或模式

报告始终包含：
- **执行摘要**（项目概述、按严重程度统计的发现总数、整体风险态势）
- **发现汇总表**（所有发现集中展示，便于快速扫描）
- **详细发现**（每个发现一节，含以上 7 个字段）
- **附录**（完整技术栈清单、辅助工具运行情况说明）

---

## 审计工作流

1. **环境检测** — 检查三个辅助工具是否可用，若不可用且有网络则运行安装脚本，离线环境则跳过。
2. **侦察** — 读取 go.mod，扫描目录结构，撰写侦察摘要。若 `govulncheck` 可用则运行。
3. **攻击面梳理** — 列出所有入口点，标记高风险模块。
4. **辅助扫描** — 若 `gosec` / `staticcheck` 可用则运行，收集结果作为参考。
5. **手动审计** — 使用 `references/go-security-rules.md` 中的规则逐一检查每个高风险模块。
6. **报告** — 按照 `references/report-template.md` 中的结构撰写完整报告，保存为项目根目录下的 `安全审计报告.md`。

**大型代码库（>50 个 Go 文件）的优先级：** 入口点处理器 → 认证/鉴权中间件 → 数据库/查询层 → 文件操作 → 出站 HTTP → 配置/密钥加载。

如果用户指定了关注区域（例如"重点审计支付模块"），优先审计该区域，但仍对整个代码库进行较轻量的全面检查。

---

## 参考文件

- `references/go-security-rules.md` — Go 专项漏洞模式完整检查表，含检测启发式规则和 Go 标准库陷阱。审计每个漏洞类别时读取。
- `references/report-template.md` — 撰写输出报告时使用的精确 Markdown 模板。
- `references/offline-setup.md` — 离线/内网环境下安装辅助工具的详细方案（含 Docker 镜像、内网代理、本地漏洞数据库）。
- `scripts/install_tools.sh` — 一键安装辅助工具的脚本（有网络时使用）。
