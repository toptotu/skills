# 追踪项目清单

本文档列出 go-security-tracker 默认追踪的 Go 开源项目，包含项目背景、安全历史和关注重点。

## 容器与编排

### kubernetes/kubernetes
- **模块路径**: `k8s.io/kubernetes`
- **安全重点**: API server 认证绕过、etcd 访问控制、RBAC 绕过、admission webhook
- **历史高危**: CVE-2019-11253 (YAML DoS), CVE-2021-25735 (admission validation bypass)
- **CVE 频率**: 高，每月约 3-8 条

### moby/moby (Docker Engine)
- **模块路径**: `github.com/docker/docker`
- **安全重点**: 容器逃逸、镜像构建安全、API 认证
- **历史高危**: CVE-2019-5736 (runc 容器逃逸), CVE-2022-36109 (supplementary groups 绕过)
- **CVE 频率**: 中，每月约 1-3 条

### containerd/containerd
- **模块路径**: `github.com/containerd/containerd`
- **安全重点**: OCI 镜像规范合规、snapshotter 路径安全、shim 通信
- **历史高危**: CVE-2022-23648 (路径遍历), CVE-2021-41190 (符号链接攻击)
- **CVE 频率**: 中

### helm/helm
- **模块路径**: `helm.sh/helm/v3`
- **安全重点**: Chart 模板注入、YAML 解析器、TLS 校验
- **历史高危**: CVE-2019-25210 (info disclosure), CVE-2021-32690 (凭证泄露)
- **CVE 频率**: 低

### opencontainers/runc
- **安全重点**: Linux namespace 逃逸、/proc 竞争、cgroup 绕过
- **历史高危**: CVE-2019-5736 (最著名容器逃逸)
- **CVE 频率**: 低，但每条都很严重

---

## 服务网格与网络

### istio/istio
- **安全重点**: mTLS 绕过、授权策略逻辑错误、Envoy sidecar 注入安全
- **历史高危**: CVE-2022-21679 (认证绕过), CVE-2023-44487 (HTTP/2 DoS)
- **CVE 频率**: 中

### cilium/cilium
- **安全重点**: BPF 程序安全、网络策略旁路、hubble 信息泄露
- **CVE 频率**: 低

### traefik/traefik
- **模块路径**: `github.com/traefik/traefik/v2`
- **安全重点**: 路由配置注入、中间件绕过、TLS 配置
- **历史高危**: CVE-2022-23469 (ReDoS), CVE-2023-29013 (HTTP 头注入)
- **CVE 频率**: 中

### coredns/coredns
- **安全重点**: DNS 放大攻击、插件安全、DNSSEC 验证
- **CVE 频率**: 低

---

## 数据库与存储

### etcd-io/etcd
- **模块路径**: `go.etcd.io/etcd/v3`
- **安全重点**: Raft 日志安全、gRPC 认证、快照完整性
- **历史高危**: CVE-2020-15106 (大包 DoS), CVE-2021-28235 (认证绕过)
- **CVE 频率**: 低

### pingcap/tidb
- **安全重点**: SQL 注入（罕见）、权限控制、TLS 配置
- **CVE 频率**: 低

---

## 密钥管理与认证

### hashicorp/vault
- **模块路径**: `github.com/hashicorp/vault`
- **安全重点**: 密钥泄露、Token 伪造、审计日志绕过、Seal 机制
- **历史高危**: CVE-2020-16250 (AWS auth 绕过), CVE-2021-3024 (信息泄露)
- **CVE 频率**: 中

### hashicorp/consul
- **安全重点**: ACL 绕过、服务网格认证、DNS 安全
- **历史高危**: CVE-2021-37219 (Raft RPC DoS)
- **CVE 频率**: 低

### cert-manager/cert-manager
- **安全重点**: ACME 验证绕过、证书签发权限、Webhook 安全
- **CVE 频率**: 低

---

## 可观测性

### prometheus/prometheus
- **模块路径**: `github.com/prometheus/prometheus`
- **安全重点**: SSRF（远程 scrape）、规则注入、Web UI XSS
- **历史高危**: CVE-2019-3826 (开放重定向 SSRF)
- **CVE 频率**: 低

### grafana/grafana
- **模块路径**: `github.com/grafana/grafana`
- **安全重点**: SQL 注入（datasource）、SSRF（plugin）、权限提升、SSTI
- **历史高危**: CVE-2021-43798 (路径遍历, 极高危！), CVE-2022-21673 (信息泄露)
- **CVE 频率**: 高，每月约 1-4 条

---

## CI/CD

### argoproj/argo-cd
- **模块路径**: `github.com/argoproj/argo-cd/v2`
- **安全重点**: Helm/Kustomize 仓库 SSRF、RBAC 绕过、secret 访问
- **历史高危**: CVE-2022-24348 (路径遍历 secret 访问), CVE-2023-22482 (认证绕过)
- **CVE 频率**: 高

### go-gitea/gitea
- **模块路径**: `code.gitea.io/gitea`
- **安全重点**: 命令注入（git hooks）、SSRF、权限提升、XSS
- **历史高危**: CVE-2022-1928 (XSS), CVE-2023-22464 (权限提升)
- **CVE 频率**: 高

### fluxcd/flux2
- **安全重点**: OCI 镜像验证绕过、RBAC 配置、Helm 仓库 SSRF
- **CVE 频率**: 低

---

## 运行时与工具链

### golang/go (标准库)
- **安全重点**: net/http 安全、crypto 包漏洞、unsafe 相关
- **历史高危**: CVE-2023-44487 (HTTP/2 Rapid Reset), CVE-2023-39325 (HTTP/2 DoS)
- **CVE 频率**: 中，每个 Go 版本约 3-8 条安全修复

### grpc/grpc-go
- **模块路径**: `google.golang.org/grpc`
- **安全重点**: 消息大小限制、TLS 配置、认证拦截器
- **CVE 频率**: 低

### google/go-containerregistry
- **安全重点**: 镜像拉取认证、layer 验证
- **CVE 频率**: 低

---

## 自定义项目配置

如需追踪额外项目，在 `~/.go-security-tracker/config.json` 中添加：

```json
{
  "tracked_repos": [
    "yourorg/your-go-project",
    "kubernetes/kubernetes"
  ]
}
```

或在命令行指定：

```bash
python3 scripts/fetch_advisories.py --repo yourorg/project --repo kubernetes/kubernetes
```
