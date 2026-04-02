# 离线环境配置说明

本技能在执行辅助静态分析时会使用三个外部工具：`govulncheck`、`gosec`、`staticcheck`。这些工具**不是必须的**——即使无法运行它们，技能仍会完整执行手动代码审计并输出漏洞报告。但若能运行，它们可以作为辅助扫描手段，补充发现更多问题。

---

## 工具说明

| 工具 | 用途 | 官方来源 |
|---|---|---|
| `govulncheck` | 扫描 go.mod 依赖中已知 CVE | `golang.org/x/vuln` |
| `gosec` | Go 代码 SAST，检测常见安全模式 | `github.com/securego/gosec` |
| `staticcheck` | Go 静态分析，含安全相关检查 | `honnef.co/go/tools` |

---

## 在线环境（有公网访问）

直接运行安装脚本：

```bash
bash skills/go-security-audit-cn/scripts/install_tools.sh
```

脚本会通过 `go install` 下载并编译三个工具，存放在 `$GOPATH/bin`（默认 `~/go/bin`）。

---

## 离线环境（无公网访问）

### 方案一：在有网机器上预先编译，拷贝二进制

在一台**同架构、同 OS** 的联网机器上执行：

```bash
GOBIN=/tmp/go-audit-tools go install golang.org/x/vuln/cmd/govulncheck@latest
GOBIN=/tmp/go-audit-tools go install github.com/securego/gosec/v2/cmd/gosec@latest
GOBIN=/tmp/go-audit-tools go install honnef.co/go/tools/cmd/staticcheck@latest
```

然后将 `/tmp/go-audit-tools/` 目录打包，传输到目标机器，放入任意 `PATH` 目录下（如 `/usr/local/bin/`）：

```bash
# 打包
tar -czf go-audit-tools.tar.gz -C /tmp go-audit-tools

# 在目标机器上解包
tar -xzf go-audit-tools.tar.gz
sudo cp go-audit-tools/* /usr/local/bin/
chmod +x /usr/local/bin/govulncheck /usr/local/bin/gosec /usr/local/bin/staticcheck
```

### 方案二：离线构建（使用 Go 模块代理缓存）

若内网有 **Athens / GOPROXY 私有代理**，在目标机器上设置代理后直接安装：

```bash
export GONOSUMCHECK=*
export GOFLAGS=-mod=mod
export GOPROXY=http://<你的内网代理地址>

go install golang.org/x/vuln/cmd/govulncheck@latest
go install github.com/securego/gosec/v2/cmd/gosec@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
```

### 方案三：使用 Docker 预制镜像（推荐）

若环境支持 Docker，可将工具打包进镜像。以下 Dockerfile 供参考：

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

构建镜像（在联网机器上）：

```bash
docker build -t go-audit-tools:latest -f Dockerfile.audit .
docker save go-audit-tools:latest | gzip > go-audit-tools.tar.gz
```

传输到目标机器后导入：

```bash
docker load < go-audit-tools.tar.gz
```

使用时挂载项目目录运行：

```bash
docker run --rm -v $(pwd):/workspace go-audit-tools:latest \
    sh -c "cd /workspace && gosec ./... 2>&1"
```

---

## 验证安装是否成功

```bash
govulncheck --version
gosec --version
staticcheck --version
```

三条命令均输出版本号说明安装成功。若任意一个不可用，技能将跳过对应工具的扫描步骤，仅基于手动代码审计生成报告，并在报告末尾注明哪些工具未运行。

---

## govulncheck 的离线漏洞数据库

`govulncheck` 默认从 `https://vuln.go.dev` 下载漏洞数据库。离线环境下需要本地镜像：

```bash
# 在联网机器上下载数据库快照
git clone https://github.com/golang/vulndb /opt/vulndb

# 在目标机器上使用本地数据库
export GOVULNDB=file:///opt/vulndb
govulncheck ./...
```

或直接跳过 govulncheck，仅使用 gosec 和 staticcheck（二者不依赖外部漏洞数据库）。
