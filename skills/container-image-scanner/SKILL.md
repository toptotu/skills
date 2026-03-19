---
name: container-image-scanner
description: 扫描容器镜像安全漏洞，生成基于 CIS Docker Benchmark 的安全测试报告。本地化运行，默认无需联网。适用场景：扫描 Docker/OCI 镜像 CVE 漏洞、检查 CIS Docker Benchmark 合规性、分析 Dockerfile 安全配置、生成容器安全审计报告、内网/离线/隔离环境安全扫描、评估镜像安全态势。用户说"扫我的镜像"、"检查容器安全"、"这个镜像安全吗"时均触发。
---

# 容器镜像安全扫描器（本地化 · 无需联网）

本技能使用 **Trivy**（本地安装）扫描容器镜像，基于 **CIS Docker Benchmark v1.6** 进行安全检查，生成 HTML 和 Markdown 格式的安全报告。

**核心设计原则：扫描过程完全本地化，无需网络连接。**

---

## 快速开始

### 前置条件检查

```bash
python3 scripts/setup_trivy.py --check
```

输出示例：

```
✅ Trivy 二进制  : /home/ubuntu/.local/bin/trivy
   版本           : Version: 0.69.3
✅ 漏洞数据库    : ~/.cache/trivy/db/trivy.db（2 天前更新）

✅ 已就绪：可执行离线扫描（无需网络）
```

### 扫描镜像（本地 Docker daemon 中已有的镜像）

```bash
# 扫描本地镜像（无需网络）
python3 scripts/scan_image.py --image nginx:latest --output-dir ./report

# 生成报告
python3 scripts/generate_report.py \
  --scan-json ./report/scan_results.json \
  --output-dir ./report \
  --image nginx:latest
```

### 扫描本地 tar 包（完全离线，无需 Docker daemon）

```bash
# 从 tar 文件扫描（docker save 导出的镜像）
python3 scripts/scan_image.py --input /path/to/myapp.tar --output-dir ./report

# 或扫描 OCI 格式目录
python3 scripts/scan_image.py --input /path/to/oci-dir/ --output-dir ./report
```

---

## 扫描目标类型

| 参数 | 描述 | 是否需要网络 |
|------|------|------------|
| `--image NAME:TAG` | 本地 Docker daemon 中的镜像 | 否（镜像已在本地） |
| `--input /path/to/image.tar` | `docker save` 导出的 tar 文件 | 否（完全离线） |
| `--input /path/to/oci-dir/` | OCI 镜像目录 | 否（完全离线） |
| `--dockerfile /path/to/Dockerfile` | Dockerfile 文件 | 否（内置规则） |

**tar 包扫描示例（最彻底的离线模式）：**

```bash
# 在有 Docker 的机器上导出镜像
docker save myapp:1.0 -o myapp.tar
# 传输到目标机器，完全离线扫描
python3 scripts/scan_image.py --input myapp.tar --output-dir ./report --scan-secrets
```

---

## 安装 Trivy（多种方式）

### 方式一：系统包管理器（推荐内网环境，需配置内网源）

```bash
# 使用系统包管理器安装（需要 apt/yum/brew 已配置内网 Trivy 源）
python3 scripts/setup_trivy.py --pkg-manager

# 等效手动命令（Ubuntu/Debian）
sudo apt-get install -y trivy

# 等效手动命令（RHEL/CentOS）
sudo yum install -y trivy
```

### 方式二：本地二进制文件

```bash
# 如果已有 trivy 可执行文件
python3 scripts/setup_trivy.py --local-binary /path/to/trivy
```

### 方式三：本地 tar 归档

```bash
# 从本地 tarball 安装（从内网文件服务器下载）
python3 scripts/setup_trivy.py --local-archive /path/to/trivy_0.69.3_Linux-64bit.tar.gz
```

### 方式四：网络下载（仅在有公网时使用）

```bash
python3 scripts/setup_trivy.py --download
```

---

## 漏洞数据库管理（完全离线）

### 离线导入 DB（推荐内网/隔离环境）

在**有网络的机器**上打包：

```bash
# 打包 Trivy 二进制 + 漏洞数据库为离线包
python3 scripts/prepare_offline.py --package /tmp/trivy-bundle --update-db
```

生成文件：
```
/tmp/trivy-bundle/
├── trivy_Linux-64bit.tar.gz    # Trivy 二进制（约 50MB）
├── trivy-db.tar.gz             # 漏洞数据库（约 1GB）
├── trivy-policy.tar.gz         # CIS 检查规则（约 100KB）
└── offline-manifest.json       # 版本清单
```

在**目标（离线）机器**上导入：

```bash
# 步骤 1：安装 Trivy 二进制
python3 scripts/setup_trivy.py --local-archive /path/to/trivy_Linux-64bit.tar.gz

# 步骤 2：导入漏洞数据库
python3 scripts/setup_trivy.py --db-archive /path/to/trivy-db.tar.gz

# 步骤 3：验证
python3 scripts/setup_trivy.py --check
```

### 自定义缓存目录

```bash
# 使用非默认缓存目录（共享存储、NFS 等场景）
python3 scripts/setup_trivy.py --db-archive /path/to/trivy-db.tar.gz --cache-dir /opt/trivy-cache

# 扫描时也指定相同缓存目录
python3 scripts/scan_image.py --image myapp:1.0 --cache-dir /opt/trivy-cache --output-dir ./report
```

### 联网更新 DB（可选，有网络时使用）

```bash
# 只更新 DB，不重装 Trivy
python3 scripts/setup_trivy.py --update-db

# 或在扫描时临时更新
python3 scripts/scan_image.py --image myapp:1.0 --update-db --output-dir ./report
```

---

## 完整工作流程

### 步骤 1 — 确认 Trivy 就绪

```bash
python3 scripts/setup_trivy.py --check
```

如未就绪，根据提示选择安装方式：

```
❌ Trivy 二进制  : 未找到
   解决方案:
   - 系统包管理器 : python3 setup_trivy.py --pkg-manager
   - 本地文件     : python3 setup_trivy.py --local-binary /path/to/trivy
   - 本地归档     : python3 setup_trivy.py --local-archive /path/to/trivy.tar.gz
   - 网络下载     : python3 setup_trivy.py --download
```

### 步骤 2 — 运行扫描

```bash
# 扫描本地镜像（最常见）
python3 scripts/scan_image.py \
  --image myapp:1.0 \
  --output-dir ./scan-results \
  --scan-secrets

# 扫描 tar 包（完全无需 Docker）
python3 scripts/scan_image.py \
  --input myapp.tar \
  --output-dir ./scan-results \
  --scan-secrets

# 同时扫描镜像 + Dockerfile
python3 scripts/scan_image.py \
  --image myapp:1.0 \
  --dockerfile ./Dockerfile \
  --output-dir ./scan-results
```

### 步骤 3 — 生成报告

```bash
python3 scripts/generate_report.py \
  --scan-json ./scan-results/scan_results.json \
  --output-dir ./scan-results \
  --image myapp:1.0 \
  --format both
```

报告文件：
- `./scan-results/security-report.html` — 交互式 HTML 报告
- `./scan-results/security-report.md`  — Markdown 报告

---

## 扫描选项说明

### 网络控制（默认均为关闭）

| 参数 | 默认 | 说明 |
|------|------|------|
| `--update-db` | 否 | 扫描前联网更新漏洞库 |
| `--pull` | 否 | 允许从远程 Registry 拉取镜像 |
| *(无参数)* | ✅ | 完全离线，使用本地缓存 |

### 关键 Trivy 标志（自动传入）

```
--skip-db-update       # 不更新漏洞库（离线默认）
--skip-java-db-update  # 不更新 Java 依赖库（离线默认）
--offline-scan         # 不发起任何外部 API 请求（离线默认）
```

---

## CIS Docker Benchmark 覆盖范围

扫描检查以下 CIS Docker Benchmark v1.6 控制项（Section 4：容器镜像）：

| 检查 ID | CIS 章节 | 描述 | 级别 |
|---------|---------|------|------|
| DS-0002 | CIS 4.1 | 镜像用户不应为 root | L1 |
| DS-0004 | CIS 5.7 | 不应暴露 22（SSH）端口 | L1 |
| DS-0005 | CIS 4.9 | 使用 COPY 代替 ADD | L1 |
| DS-0017 | CIS 4.7 | 不单独使用 update 指令 | L1 |
| DS-0026 | CIS 4.6 | 添加 HEALTHCHECK 指令 | L1 |
| DS-0029 | CIS 4.3 | apt-get 使用 --no-install-recommends | L1 |
| DS-0031 | CIS 4.10 | Dockerfile 中不存储密钥 | L1 |

---

## 报告结构

```
# 容器镜像安全报告
## 元信息（镜像、扫描日期、工具版本）
## 执行摘要
  - 整体风险等级：CRITICAL / HIGH / MEDIUM / LOW
  - CIS 合规度：X/Y 项通过（Z%）
  - 各严重度漏洞数量
## CIS Docker Benchmark 合规（Section 4）
  - 控制项表格：ID | 描述 | 状态 | 严重度
## CVE 漏洞详情
  - 按严重度排序
  - 每条：CVE编号 | 包名 | 当前版本 | 修复版本 | CVSS | 描述
## 配置问题（Misconfigurations）
  - 每条：ID | 标题 | 严重度 | 修复建议
## 密钥泄露（如开启 --scan-secrets）
## 修复建议
  - 优先级排序的行动清单
## 附录（方法论、工具版本）
```

---

## 参考文件

- `references/cis_docker_benchmark.md` — CIS Docker Benchmark Section 4 完整控制项（含修复指南和 CI/CD 集成示例）
- `references/trivy_output_schema.md` — Trivy JSON 输出格式参考
