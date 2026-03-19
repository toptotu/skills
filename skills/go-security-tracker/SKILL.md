---
name: go-security-tracker
description: 每日自动抓取业界著名开源 Go 项目的最新安全漏洞和修复方案，总结漏洞特征与防御策略，生成安全日报。作为 Go 语言安全 review 专家辅助工具使用。触发场景：用户询问 Go 项目安全漏洞、要求生成安全日报、查询特定 Go 项目 CVE、分析 Go 代码安全模式、制定 Go 安全加固方案、或提到需要关注 kubernetes/docker/etcd/helm/vault 等 Go 项目安全动态时均应触发本技能。
---

# Go 语言开源项目安全追踪器

作为 Go 语言安全 review 专家，本技能每日自动从多个权威来源抓取知名 Go 开源项目的最新安全漏洞信息，分析漏洞特征，生成带有防御方案的安全日报。

## 追踪的项目

覆盖业界最广泛使用的 Go 开源项目：

| 类别 | 项目 |
|------|------|
| 容器/编排 | kubernetes/kubernetes, moby/moby, containerd/containerd, helm/helm |
| 服务网格/网络 | istio/istio, cilium/cilium, traefik/traefik |
| 数据库/存储 | etcd-io/etcd, pingcap/tidb, cockroachdb/cockroach |
| 密钥/认证 | hashicorp/vault, hashicorp/consul, cert-manager/cert-manager |
| 可观测性 | prometheus/prometheus, grafana/grafana, open-telemetry/opentelemetry-go |
| CI/CD | argoproj/argo-cd, go-gitea/gitea, harness/gitness |
| 运行时/工具链 | golang/go (标准库), grpc/grpc-go, google/go-containerregistry |

## 数据来源

1. **Go 官方漏洞库** — https://vuln.go.dev (OSV 格式，最权威)
2. **OSV 数据库** — https://api.osv.dev/v1/query (覆盖 Go 生态系)
3. **GitHub Security Advisories** — GraphQL API (需要 GitHub Token)
4. **NVD API v2** — https://services.nvd.nist.gov/rest/json/cves/2.0 (美国 NIST CVE)

## 代理配置

公司内网环境下，脚本自动读取以下代理环境变量：
- `HTTPS_PROXY` / `HTTP_PROXY` / `ALL_PROXY`
- `GO_SECURITY_PROXY` (自定义代理，优先级最高)

也可以通过配置文件 `~/.go-security-tracker/config.json` 静态配置代理。

运行前可用脚本快速验证代理连通性：
```bash
python3 scripts/check_proxy.py
```

---

## 工作流程

### 步骤 1 — 确认配置

首次使用时，运行配置向导：

```bash
python3 scripts/setup_config.py
```

它会引导用户配置：
- 代理地址（可选）
- GitHub Token（可选，用于访问 GitHub Advisory API）
- 追踪项目列表（可自定义，默认覆盖上述全部项目）
- 输出目录（默认 `./go-security-reports/`）
- 日报语言（中文/English，默认中文）

配置保存到 `~/.go-security-tracker/config.json`。

### 步骤 2 — 抓取安全数据

```bash
python3 scripts/fetch_advisories.py [--days 1] [--output-dir ./reports]
```

参数说明：
- `--days N`：抓取最近 N 天的数据（日报用 1，周报用 7，默认 1）
- `--output-dir PATH`：原始数据输出目录
- `--proxy URL`：临时指定代理（覆盖环境变量）
- `--source all|goosv|github|nvd`：指定数据源（默认 all）
- `--repo owner/name`：只抓取特定仓库（可多次使用）

原始数据保存到 `<output-dir>/raw/<date>/advisories.json`。

### 步骤 3 — 生成安全日报

```bash
python3 scripts/generate_digest.py \
  --raw-file ./reports/raw/<date>/advisories.json \
  --output-dir ./reports \
  [--format html|markdown|both]
```

生成文件：
- `go-security-digest-<date>.html`：交互式 HTML 日报（含漏洞分类、防御建议）
- `go-security-digest-<date>.md`：Markdown 版本，适合发布到内部 Wiki/Confluence

### 步骤 4 — 展示结果

生成后，向用户展示：
1. **当日漏洞速览**：总数、严重度分布、最高危漏洞
2. **受影响最多的项目 Top 5**
3. **本期漏洞特征总结**（基于 `references/go_vuln_patterns.md` 分类）
4. **防御建议摘要**
5. 告知完整报告路径

---

## 定时自动运行

在 Linux/macOS 上配置 cron 任务，每天 8:00 自动运行：

```bash
# 查看并编辑 crontab
crontab -e

# 添加以下行（替换路径）
0 8 * * * cd /path/to/skill && \
  HTTPS_PROXY=http://proxy.company.com:8080 \
  python3 scripts/fetch_advisories.py --days 1 --output-dir ~/go-security-reports && \
  python3 scripts/generate_digest.py \
    --raw-file ~/go-security-reports/raw/$(date +\%Y-\%m-\%d)/advisories.json \
    --output-dir ~/go-security-reports \
  >> ~/go-security-reports/cron.log 2>&1
```

完整的一键运行脚本：

```bash
python3 scripts/run_daily.py [--output-dir ~/go-security-reports]
```

---

## 报告结构

生成的日报包含以下章节：

```
# Go 开源项目安全日报 <日期>
## 执行摘要
  - 新增漏洞总数 / 严重程度分布
  - 高危漏洞速览（CRITICAL/HIGH）
  - 受影响项目统计
## 漏洞详情（按严重度排序）
  每条漏洞包含：
  - CVE/GHSA/GO-XXXX 编号
  - 受影响项目 & 版本范围
  - 漏洞类型（注入/越权/拒绝服务/信息泄露等）
  - 漏洞原理简述
  - PoC/利用条件
  - 修复版本 & 修复方案
  - 临时缓解措施
## 漏洞特征分析
  - 本期主要漏洞类型分布
  - 高频漏洞模式（对照 Go 安全编码规范）
  - 与上期对比趋势
## 防御建议
  - 针对本期漏洞的具体加固措施
  - 代码 review 重点提示
  - 依赖版本升级清单
## 漏洞指纹库更新
  - 本期新增漏洞特征（可导入到静态分析工具规则）
```

---

## 漏洞分类体系

本技能将 Go 漏洞按以下类型分类（详见 `references/go_vuln_patterns.md`）：

| 类型代码 | 中文名称 | Go 典型场景 |
|---------|---------|-----------|
| G-INJ | 注入类 | SQL注入、命令注入、LDAP注入、模板注入 |
| G-AUTH | 认证/授权绕过 | JWT 伪造、RBAC 绕过、权限提升 |
| G-DOS | 拒绝服务 | 正则回溯、内存耗尽、goroutine 泄漏、HTTP/2 Reset |
| G-MEM | 内存安全 | unsafe 使用不当、cgo 边界问题 |
| G-PROTO | 协议/序列化 | Protobuf 炸弹、YAML/JSON 解析器漏洞 |
| G-CRYPTO | 密码学 | 弱随机数、证书校验绕过、TLS 配置错误 |
| G-SSRF | 服务端请求伪造 | http.Client 未限制重定向、内网探测 |
| G-PATH | 路径遍历 | filepath.Join 绕过、符号链接攻击 |
| G-RACE | 竞争条件 | map 并发写、time-of-check/time-of-use |
| G-SUPPLY | 供应链 | 恶意依赖、typosquatting、模块代理攻击 |

---

## Go 安全漏洞特征与防御参考

详细的漏洞模式和防御方案参见：
- `references/go_vuln_patterns.md` — Go 特有漏洞模式详解（含代码示例）
- `references/go_defense_strategies.md` — 防御方案和加固 checklist
- `references/tracked_projects.md` — 追踪项目清单及其安全历史

---

## 代理故障排查

如遇网络问题：

```bash
# 检查代理配置
python3 scripts/check_proxy.py

# 指定代理手动运行
python3 scripts/fetch_advisories.py --proxy http://proxy.company.com:8080

# 离线模式（只使用本地缓存）
python3 scripts/fetch_advisories.py --offline

# 查看详细网络日志
python3 scripts/fetch_advisories.py --verbose
```

常见代理问题：
- **SSL 证书验证失败**：设置 `REQUESTS_CA_BUNDLE=/path/to/company-ca.pem` 或使用 `--no-verify-ssl`（不推荐生产使用）
- **NTLM 代理认证**：安装 `pip install requests-ntlm` 并在 config.json 中配置 `ntlm_auth`
- **SOCKS5 代理**：`ALL_PROXY=socks5://proxy:1080`（需要 `pip install requests[socks]`）
