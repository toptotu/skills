---
name: container-image-audit
description: 以容器安全渗透测试专家视角对容器镜像进行深度安全审计，输出含攻击链分析的渗透测试报告。适用场景：对镜像软件包进行安全审计、评估容器逃逸风险、识别攻击者入侵后可利用的武器库、分析层历史中泄露的密钥、生成可落地的高优先级修复建议。用户说"审计镜像"、"对镜像做渗透测试"、"评估容器安全"、"找容器里的漏洞"时均触发。
---

# 容器镜像安全审计技能（渗透测试视角）

以**攻击者思维**对容器镜像进行系统性安全审计，输出**可操作、低误报、高优先级**的渗透测试报告。

## 核心审计方法论

### 三阶段审计框架

```
Phase 1 快速定性 (5分钟)          Phase 2 深度分析 (20分钟)          Phase 3 利用评估 (10分钟)
─────────────────────             ──────────────────────────────      ──────────────────────
• 基础信息 & EOL 判断             • 全量 CVE 扫描 + 利用链分析          • 攻击场景建模
• CRITICAL CVE + PoC 可用性       • 层历史 & 已删文件密钥                • 前置条件评估
• 明显密钥泄露                    • 危险二进制清单                       • 逃逸向量分析
• root 运行判断                   • SBOM + 攻击面映射                    • 影响半径评估
```

### 低误报原则

1. **CVE 过滤**：只报告有修复版本 + CVSS ≥ 7.0 或有公开 PoC 的漏洞
2. **密钥验证**：通过熵值计算 + 模式匹配双重验证，减少假阳性
3. **分层去重**：同一 CVE 跨多层/多包只报告一次
4. **置信度标注**：每个发现标注置信度（确认/疑似/信息）

---

## 工作流程

### 步骤 1 — 前置检查

确保 Trivy 已安装（离线模式）：
```bash
python3 ../container-image-scanner/scripts/setup_trivy.py --check
```

### 步骤 2 — 执行完整审计

```bash
# 审计本地镜像
python3 scripts/audit_image.py \
  --image nginx:latest \
  --output-dir ./audit-report \
  [--phase all|quick|deep|exploit]

# 审计本地 tar 包（完全离线）
python3 scripts/audit_image.py \
  --input /path/to/myapp.tar \
  --output-dir ./audit-report

# 仅执行快速定性（5分钟）
python3 scripts/audit_image.py --image myapp:1.0 --phase quick

# 含层历史分析（需要 Docker）
python3 scripts/audit_image.py --image myapp:1.0 --with-layer-analysis
```

### 步骤 3 — 生成渗透测试报告

```bash
python3 scripts/generate_audit_report.py \
  --audit-json ./audit-report/audit_results.json \
  --output-dir ./audit-report \
  --format html
```

### 步骤 4 — 结果呈现

生成报告后，向用户展示：
1. **风险等级矩阵**：确认 / 高危 / 中危 / 低危 的数量
2. **Top 5 攻击路径**：最可利用的漏洞链
3. **危险资产清单**：攻击者入侵后可直接使用的工具
4. **立即行动项**：3 个最高优先级修复建议

---

## 审计维度详解

### 维度 1：CVE 漏洞 + 可利用性评估

不是所有 CVE 都需要修复。按以下优先级排序：

| 优先级 | 条件 | 行动 |
|--------|------|------|
| P0 🔴 | CVSS ≥ 9.0 + 公开 exploit + 有修复版本 | 立即修复，阻断部署 |
| P1 🟠 | CVSS ≥ 7.0 + 可网络利用 + 有修复版本 | 7天内修复 |
| P2 🟡 | CVSS 4.0-6.9 + 有修复版本 | 下次发布修复 |
| P3 🟢 | 无修复版本 / CVSS < 4.0 | 记录观察 |

### 维度 2：层历史分析（攻击者最爱）

Docker 镜像每层都保留历史记录，**即使文件在后续层中被删除，仍可在该层中提取**。

重点检查：
- `RUN` 指令中的明文密码（`apt-get install -y --password=...`）
- 被 `RUN rm` 删除的配置文件
- `COPY` / `ADD` 后被清除的证书/密钥文件
- `ENV` 指令中的 API Key（永久存储在层中）

```bash
# 查看层历史
docker history --no-trunc <image>

# 提取特定层内容分析
python3 scripts/analyze_layers.py --image <image> --output-dir ./audit-report
```

### 维度 3：危险二进制清单（攻击者武器库）

攻击者获得容器 shell 后，可利用容器内的工具进行**横向移动**和**数据外泄**：

| 危险程度 | 工具 | 攻击者用途 |
|---------|------|----------|
| 🔴 高危 | `curl`, `wget` | 下载 payload、反弹 shell、数据外泄 |
| 🔴 高危 | `nc`/`netcat`, `socat` | 建立隐蔽通道、端口转发 |
| 🔴 高危 | `python3`, `perl`, `ruby` | 执行任意代码 |
| 🟠 中危 | `bash`, `sh`, `zsh` | 交互式 shell 会话 |
| 🟠 中危 | `ssh`, `scp` | 横向移动 |
| 🟠 中危 | `nmap`, `masscan` | 内网扫描 |
| 🟡 低危 | `gcc`, `make` | 编译 exploit |
| 🟡 低危 | `git` | 代码/工具下载 |

详见 `references/dangerous_binaries.md`

### 维度 4：权限提升向量

```
SUID 二进制 ──► 本地提权
Capabilities ──► 逃逸沙箱
root 运行 ──► 宿主机资源访问
可写挂载点 ──► 持久化
```

### 维度 5：容器逃逸风险评估

基于静态分析评估逃逸风险（运行时确认）：

| 风险项 | 检测方法 | 逃逸路径 |
|--------|---------|---------|
| root 运行 | 检查 User 字段 | 配合内核漏洞逃逸 |
| 危险 capabilities | `docker inspect` | `CAP_SYS_ADMIN` 等可直接逃逸 |
| SUID/SGID 二进制 | `find / -perm -4000` | 本地提权 → 逃逸 |
| 可写 /proc / /sys | 运行时检查 | 内核攻击面扩大 |

---

## 报告结构

```
# 容器镜像安全审计报告（渗透测试视角）
## 执行摘要
  - 整体风险评级 / 可利用发现数 / 立即行动项
## 攻击场景建模
  - 攻击者入侵后的能力地图
  - Top 5 攻击路径（完整链）
## P0/P1 高危发现（需立即处理）
  - 每条：CVE/发现类型 | 利用条件 | 攻击效果 | 修复方案
## CVE 漏洞详情（按可利用性排序）
## 危险资产清单（攻击者武器库）
## 层历史安全分析
## 配置合规检查（CIS Benchmark）
## 软件物料清单（SBOM）
## 修复优先级矩阵
```

---

## 参考资料

- `references/attack_patterns.md` — 容器攻击模式与利用链（含真实 CVE 案例）
- `references/dangerous_binaries.md` — 危险二进制详细说明与攻击者用法
- `references/escape_vectors.md` — 容器逃逸向量与检测方法
- `../container-image-scanner/references/cis_docker_benchmark.md` — CIS Docker Benchmark
