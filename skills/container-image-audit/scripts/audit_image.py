#!/usr/bin/env python3
"""
容器镜像安全审计主程序（渗透测试视角）

三阶段审计：
  Phase 1 快速定性  — 5 分钟内判断风险等级
  Phase 2 深度分析  — CVE 利用链 / 层历史 / 危险二进制 / SBOM
  Phase 3 利用评估  — 攻击场景建模 / 逃逸向量 / 影响分析

默认离线运行（使用本地漏洞数据库），支持 --update-db 联网更新。

用法:
    python3 scripts/audit_image.py --image nginx:latest --output-dir ./report
    python3 scripts/audit_image.py --input myapp.tar --output-dir ./report
    python3 scripts/audit_image.py --image myapp:1.0 --phase quick
    python3 scripts/audit_image.py --image myapp:1.0 --with-layer-analysis
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

# 危险二进制列表（按风险等级）
DANGEROUS_BINARIES = {
    "CRITICAL": [
        "nc", "netcat", "ncat", "socat",
        "curl", "wget", "fetch",
        "python", "python2", "python3",
        "perl", "ruby", "lua", "node", "nodejs",
    ],
    "HIGH": [
        "bash", "sh", "zsh", "fish", "ash", "dash",
        "ssh", "scp", "sftp", "rsync",
        "nmap", "masscan", "tcpdump", "tshark",
        "strace", "ltrace", "gdb",
    ],
    "MEDIUM": [
        "gcc", "g++", "cc", "make", "cmake",
        "git", "svn", "hg",
        "tar", "unzip", "7z",
        "mysql", "psql", "redis-cli", "mongo",
        "aws", "gcloud", "az",
        "docker", "kubectl", "helm",
    ],
    "LOW": [
        "vim", "vi", "nano", "emacs",
        "base64", "xxd", "od",
        "cron", "crontab", "at",
    ],
}

# 高风险 Linux capabilities
DANGEROUS_CAPABILITIES = {
    "CAP_SYS_ADMIN":   "CRITICAL — 可挂载文件系统、操作内核参数，最强容器逃逸能力",
    "CAP_SYS_PTRACE":  "CRITICAL — 可追踪/注入宿主机进程",
    "CAP_NET_ADMIN":   "HIGH — 可修改网络配置、创建隧道",
    "CAP_SYS_MODULE":  "CRITICAL — 可加载内核模块，直接逃逸",
    "CAP_DAC_OVERRIDE":"HIGH — 绕过文件权限检查",
    "CAP_SETUID":      "HIGH — 可切换到任意 UID，辅助提权",
    "CAP_SYS_RAWIO":   "HIGH — 直接读写磁盘",
    "CAP_NET_RAW":     "MEDIUM — 可构造原始网络包（ARP/ICMP 攻击）",
    "CAP_CHOWN":       "MEDIUM — 可修改任意文件所有者",
    "CAP_FOWNER":      "MEDIUM — 绕过文件所有权检查",
    "CAP_AUDIT_WRITE": "LOW — 写入内核审计日志",
}

# 已知 CVE PoC 可用性标记（精选高危）
KNOWN_EXPLOITABLE_CVES = {
    "CVE-2019-5736",  "CVE-2021-30465", "CVE-2022-0492",
    "CVE-2022-23648", "CVE-2023-44487", "CVE-2023-39325",
    "CVE-2021-43798", "CVE-2021-44228", "CVE-2022-22965",
    "CVE-2019-14697", "CVE-2021-42013", "CVE-2022-24834",
    "CVE-2022-1292",  "CVE-2022-2068",
}

# 已达 EOL 的常见基础镜像（版本关键词）
EOL_PATTERNS = [
    r"ubuntu:1[024]\.", r"ubuntu:16\.", r"ubuntu:18\.",
    r"debian:8", r"debian:9", r"debian:10",
    r"centos:6", r"centos:7", r"centos:8",
    r"alpine:3\.[0-9](?!\d)",  # < 3.10
    r"python:2\.", r"python:3\.[0-7]\b",
    r"node:8\b", r"node:10\b", r"node:12\b",
    r"golang:1\.[0-9]\b", r"golang:1\.1[0-5]\b",
]


# ---------------------------------------------------------------------------
# Trivy 工具
# ---------------------------------------------------------------------------

def _find_trivy() -> str:
    p = shutil.which("trivy")
    if p:
        return p
    local = Path.home() / ".local" / "bin" / "trivy"
    if local.is_file():
        return str(local)
    raise RuntimeError(
        "未找到 trivy。请运行: python3 ../container-image-scanner/scripts/setup_trivy.py --check"
    )


def _trivy_run(trivy_bin: str, args: list[str],
               cache_dir: str | None = None) -> dict:
    """执行 trivy 命令，返回 JSON 结果。"""
    offline = ["--skip-db-update", "--skip-java-db-update", "--offline-scan"]
    cmd = [trivy_bin] + args + ["--format", "json", "--quiet", "--no-progress"] + offline
    if cache_dir:
        cmd += ["--cache-dir", cache_dir]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if not result.stdout.strip():
        return {}
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        lines = result.stdout.strip().splitlines()
        start = next((i for i, l in enumerate(lines) if l.startswith("{")), None)
        if start is not None:
            try:
                return json.loads("\n".join(lines[start:]))
            except Exception:
                pass
    return {}


def update_db(trivy_bin: str, cache_dir: str | None = None) -> None:
    cmd = [trivy_bin, "image", "--download-db-only", "--no-progress"]
    if cache_dir:
        cmd += ["--cache-dir", cache_dir]
    subprocess.run(cmd, capture_output=True)


# ---------------------------------------------------------------------------
# Phase 1: 快速定性
# ---------------------------------------------------------------------------

def phase1_quick_triage(
    trivy_bin: str,
    target: str,
    is_tar: bool,
    cache_dir: str | None,
) -> dict:
    """5 分钟快速定性：基础信息 + CRITICAL CVE + 明显密钥 + root 判断。"""
    print("  [Phase 1] 快速定性扫描...")

    target_args = ["--input", target] if is_tar else [target]

    # CVE 快速扫描（仅 CRITICAL/HIGH）
    vuln_data = _trivy_run(trivy_bin, [
        "image", "--scanners", "vuln",
        "--severity", "CRITICAL,HIGH",
        "--timeout", "3m",
    ] + target_args, cache_dir)

    # 密钥扫描
    secret_data = _trivy_run(trivy_bin, [
        "image", "--scanners", "secret",
        "--timeout", "2m",
    ] + target_args, cache_dir)

    # 提取结果
    critical_vulns = []
    high_vulns = []
    for target_r in vuln_data.get("Results", []) or []:
        for v in target_r.get("Vulnerabilities", []) or []:
            sev = v.get("Severity", "").upper()
            entry = {
                "id":      v.get("VulnerabilityID", ""),
                "pkg":     v.get("PkgName", ""),
                "version": v.get("InstalledVersion", ""),
                "fix":     v.get("FixedVersion", ""),
                "cvss":    _get_cvss(v),
                "has_fix": bool(v.get("FixedVersion")),
                "known_exploit": v.get("VulnerabilityID", "") in KNOWN_EXPLOITABLE_CVES,
                "title":   v.get("Title", "")[:80],
            }
            if sev == "CRITICAL":
                critical_vulns.append(entry)
            elif sev == "HIGH":
                high_vulns.append(entry)

    secrets = []
    for target_r in secret_data.get("Results", []) or []:
        for s in target_r.get("Secrets", []) or []:
            secrets.append({
                "rule_id":  s.get("RuleID", ""),
                "category": s.get("Category", ""),
                "title":    s.get("Title", ""),
                "severity": s.get("Severity", "HIGH"),
                "target":   target_r.get("Target", ""),
            })

    # 检查 root 运行（从 metadata 判断）
    runs_as_root = True
    meta = vuln_data.get("Metadata", {})
    user = (meta.get("ImageConfig", {}) or {}).get("config", {}).get("User", "")
    if user and user not in ("0", "root", ""):
        runs_as_root = False

    # EOL 判断
    os_info = meta.get("OS", {})
    image_eol = _check_eol(target, os_info)

    # 快速风险评级
    p0_count = sum(1 for v in critical_vulns if v["has_fix"] and v["known_exploit"])
    p1_count = sum(1 for v in critical_vulns if v["has_fix"]) + \
               sum(1 for v in high_vulns if v["has_fix"])

    if p0_count > 0 or len(secrets) > 0:
        quick_rating = "CRITICAL"
    elif p1_count >= 3 or runs_as_root:
        quick_rating = "HIGH"
    elif p1_count > 0:
        quick_rating = "MEDIUM"
    else:
        quick_rating = "LOW"

    return {
        "phase": 1,
        "quick_rating": quick_rating,
        "critical_vulns": critical_vulns[:20],
        "high_vulns":     high_vulns[:20],
        "secrets":        secrets,
        "runs_as_root":   runs_as_root,
        "image_user":     user,
        "image_eol":      image_eol,
        "os_info":        os_info,
        "image_metadata": meta,
        "p0_count":       p0_count,
        "p1_count":       p1_count,
    }


def _check_eol(target: str, os_info: dict) -> dict:
    eol = {"is_eol": False, "reason": ""}
    target_lower = target.lower()
    for pattern in EOL_PATTERNS:
        if re.search(pattern, target_lower):
            eol["is_eol"] = True
            eol["reason"] = f"镜像名称匹配 EOL 模式: {pattern}"
            return eol
    family = (os_info.get("Family") or "").lower()
    name   = (os_info.get("Name") or "").lower()
    if os_info.get("EOSL"):
        eol["is_eol"] = True
        eol["reason"] = f"操作系统已达生命周期终止: {family} {name}"
    return eol


def _get_cvss(vuln: dict) -> float | None:
    for src in (vuln.get("CVSS") or {}).values():
        for k in ("V3Score", "V2Score"):
            v = src.get(k)
            if v is not None:
                try:
                    return float(v)
                except (ValueError, TypeError):
                    pass
    return None


# ---------------------------------------------------------------------------
# Phase 2: 深度分析
# ---------------------------------------------------------------------------

def phase2_deep_analysis(
    trivy_bin: str,
    target: str,
    is_tar: bool,
    cache_dir: str | None,
    with_layer_analysis: bool = False,
    output_dir: Path = None,
) -> dict:
    """20 分钟深度分析：全量 CVE + 配置检查 + SBOM + 二进制审计。"""
    print("  [Phase 2] 深度分析...")

    target_args = ["--input", target] if is_tar else [target]

    # 全量 CVE 扫描
    print("    扫描全量 CVE 漏洞...")
    all_vuln_data = _trivy_run(trivy_bin, [
        "image", "--scanners", "vuln",
        "--timeout", "5m",
    ] + target_args, cache_dir)

    # CIS 配置检查
    print("    执行 CIS 配置检查...")
    misconfig_data = _trivy_run(trivy_bin, [
        "image", "--scanners", "misconfig",
        "--timeout", "3m",
    ] + target_args, cache_dir)

    # SBOM 生成（Trivy CycloneDX）
    print("    生成 SBOM...")
    sbom_data = _trivy_sbom(trivy_bin, target_args, cache_dir, output_dir)

    # 处理全量漏洞
    all_vulns = _collect_vulns(all_vuln_data)
    all_misconfigs = _collect_misconfigs(misconfig_data)

    # 危险二进制审计（通过 SBOM 或文件系统分析）
    print("    审计危险二进制...")
    bin_audit = _audit_dangerous_binaries(sbom_data, all_vuln_data)

    # 层历史分析（需要 Docker）
    layer_analysis = {}
    if with_layer_analysis and not is_tar:
        print("    分析层历史（检测已删文件中的密钥）...")
        layer_analysis = _analyze_layers_simple(target)

    # 统计
    vuln_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in all_vulns:
        vuln_counts[v.get("severity", "UNKNOWN")] = \
            vuln_counts.get(v.get("severity", "UNKNOWN"), 0) + 1

    return {
        "phase": 2,
        "all_vulns":      all_vulns,
        "misconfigs":     all_misconfigs,
        "sbom_summary":   sbom_data.get("summary", {}),
        "sbom_packages":  sbom_data.get("packages", []),
        "bin_audit":      bin_audit,
        "layer_analysis": layer_analysis,
        "vuln_counts":    vuln_counts,
    }


def _trivy_sbom(trivy_bin: str, target_args: list[str],
                cache_dir: str | None, output_dir: Path | None) -> dict:
    """生成 SBOM，返回包列表摘要。"""
    try:
        offline = ["--skip-db-update", "--skip-java-db-update", "--offline-scan"]
        cmd = [trivy_bin, "image", "--format", "cyclonedx", "--quiet", "--no-progress"] \
              + offline + target_args
        if cache_dir:
            cmd += ["--cache-dir", cache_dir]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        if not result.stdout.strip():
            return {}
        sbom = json.loads(result.stdout)
        components = sbom.get("components", [])
        packages = []
        for c in components:
            packages.append({
                "name":    c.get("name", ""),
                "version": c.get("version", ""),
                "type":    c.get("type", ""),
                "purl":    c.get("purl", ""),
            })
        if output_dir:
            (output_dir / "sbom.cdx.json").write_text(result.stdout, encoding="utf-8")
        return {
            "summary": {
                "total_components": len(components),
                "by_type": _count_by_type(components),
            },
            "packages": packages[:500],
        }
    except Exception:
        return {}


def _count_by_type(components: list) -> dict:
    counts = {}
    for c in components:
        t = c.get("type", "unknown")
        counts[t] = counts.get(t, 0) + 1
    return counts


def _collect_vulns(vuln_data: dict) -> list[dict]:
    vulns = []
    seen = set()
    for target_r in (vuln_data.get("Results") or []):
        for v in (target_r.get("Vulnerabilities") or []):
            vid = v.get("VulnerabilityID", "")
            pkg = v.get("PkgName", "")
            key = f"{vid}:{pkg}"
            if key in seen:
                continue
            seen.add(key)
            vulns.append({
                "vuln_id":  vid,
                "pkg":      pkg,
                "version":  v.get("InstalledVersion", ""),
                "fix":      v.get("FixedVersion", ""),
                "severity": v.get("Severity", "UNKNOWN"),
                "cvss":     _get_cvss(v),
                "title":    v.get("Title", "")[:120],
                "has_fix":  bool(v.get("FixedVersion")),
                "known_exploit": vid in KNOWN_EXPLOITABLE_CVES,
                "primary_url": v.get("PrimaryURL", ""),
                "cwe_ids":  v.get("CweIDs", []),
                "target":   target_r.get("Target", ""),
            })
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    vulns.sort(key=lambda x: (
        sev_order.get(x["severity"].upper(), 5),
        0 if x["known_exploit"] else 1,
        0 if x["has_fix"] else 1,
        -(x["cvss"] or 0),
    ))
    return vulns


def _collect_misconfigs(misconfig_data: dict) -> list[dict]:
    misconfigs = []
    for target_r in (misconfig_data.get("Results") or []):
        for m in (target_r.get("Misconfigurations") or []):
            if m.get("Status") == "PASS":
                continue
            misconfigs.append({
                "id":         m.get("ID", ""),
                "avd_id":     m.get("AVDID", ""),
                "title":      m.get("Title", ""),
                "severity":   m.get("Severity", "UNKNOWN"),
                "status":     m.get("Status", "FAIL"),
                "resolution": m.get("Resolution", ""),
                "description":m.get("Description", "")[:200],
            })
    return misconfigs


def _audit_dangerous_binaries(sbom_data: dict, vuln_data: dict) -> dict:
    """通过 SBOM 包名检测危险工具，同时检查 CVE 是否影响这些工具。"""
    found = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    packages = sbom_data.get("packages", [])
    pkg_names = {p["name"].lower() for p in packages}

    for risk, bins in DANGEROUS_BINARIES.items():
        for binary in bins:
            matches = [n for n in pkg_names if binary in n or n in binary]
            if matches:
                found[risk].append({
                    "binary": binary,
                    "package": matches[0],
                    "attack_use": _binary_attack_use(binary),
                })

    # 统计攻击工具总数
    total = sum(len(v) for v in found.values())
    return {
        "found": found,
        "total_dangerous": total,
        "attack_capability": _assess_attack_capability(found),
    }


def _binary_attack_use(binary: str) -> str:
    uses = {
        "curl":    "下载 payload / 反弹 shell / 数据外泄至 C2",
        "wget":    "下载 payload / 反弹 shell",
        "nc":      "反弹 shell / 端口转发 / 数据传输",
        "netcat":  "反弹 shell / 端口转发",
        "ncat":    "反弹 shell / 端口转发",
        "socat":   "高级隧道 / 反弹 shell / 端口转发",
        "python":  "Python 反弹 shell / 执行任意代码 / 内网扫描",
        "python2": "Python 反弹 shell / 执行任意代码",
        "python3": "Python 反弹 shell / 执行任意代码",
        "perl":    "Perl 一行 shell / 代码执行",
        "ruby":    "Ruby 反弹 shell / 代码执行",
        "bash":    "交互式 shell / 脚本执行 / 持久化",
        "sh":      "脚本执行 / 持久化",
        "ssh":     "横向移动 / 隧道穿透",
        "nmap":    "内网侦察 / 端口扫描",
        "tcpdump": "流量嗅探 / 凭证窃取",
        "strace":  "追踪系统调用 / 提取凭证",
        "gcc":     "编译 exploit / 提权工具",
        "git":     "克隆攻击工具 / 渗透框架",
        "aws":     "枚举 / 访问 AWS 资源",
        "kubectl": "枚举 Kubernetes 集群资源",
        "docker":  "容器逃逸 / 部署恶意容器",
    }
    return uses.get(binary, f"攻击者可利用 {binary} 进行后渗透操作")


def _assess_attack_capability(found: dict) -> str:
    critical_count = len(found.get("CRITICAL", []))
    high_count     = len(found.get("HIGH", []))
    if critical_count >= 2:
        return "FULL — 攻击者获得 shell 后具备完整后渗透能力（下载/隧道/代码执行）"
    elif critical_count >= 1:
        return "HIGH — 攻击者具备关键后渗透工具"
    elif high_count >= 3:
        return "MEDIUM — 攻击者具备有限后渗透能力"
    elif high_count >= 1:
        return "LOW — 攻击者有基础操作工具"
    return "MINIMAL — 镜像内危险工具极少"


def _analyze_layers_simple(image: str) -> dict:
    """简单层历史分析（使用 docker history）。"""
    try:
        result = subprocess.run(
            ["docker", "history", "--no-trunc", "--format",
             "{{.CreatedBy}}\t{{.Size}}", image],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return {"error": "docker not available"}

        suspicious = []
        secret_patterns = [
            (r'(?i)(password|passwd|pwd)\s*=\s*\S+', "明文密码"),
            (r'(?i)(api[_-]?key|apikey)\s*=\s*\S+', "API Key"),
            (r'(?i)(secret|token)\s*=\s*\S+', "密钥/Token"),
            (r'(?i)(aws_access|aws_secret)', "AWS 凭证"),
            (r'(?i)(private_key|id_rsa)', "私钥引用"),
            (r'(?i)curl\s.*-[uUpPk]', "curl 认证参数"),
            (r'RUN\s+rm\s+.*\.(key|pem|p12|pfx|crt)', "删除证书文件（层中残留）"),
        ]

        lines = result.stdout.strip().splitlines()
        for i, line in enumerate(lines):
            layer_cmd, size = (line.split("\t") + [""])[:2]
            for pattern, desc in secret_patterns:
                if re.search(pattern, layer_cmd):
                    suspicious.append({
                        "layer_index": i,
                        "layer_cmd": layer_cmd[:200],
                        "pattern":   desc,
                        "size":      size,
                    })

        return {
            "total_layers": len(lines),
            "suspicious_layers": suspicious,
            "has_suspicious": len(suspicious) > 0,
        }
    except FileNotFoundError:
        return {"error": "docker not available — layer analysis skipped"}
    except Exception as e:
        return {"error": str(e)}


# ---------------------------------------------------------------------------
# Phase 3: 利用评估
# ---------------------------------------------------------------------------

def phase3_exploit_assessment(phase1: dict, phase2: dict, target: str) -> dict:
    """攻击场景建模 + 逃逸向量评估 + 优先级矩阵。"""
    print("  [Phase 3] 利用可行性评估...")

    attack_chains = _build_attack_chains(phase1, phase2)
    escape_vectors = _assess_escape_vectors(phase1, phase2)
    priority_matrix = _build_priority_matrix(phase1, phase2)

    return {
        "phase": 3,
        "attack_chains":     attack_chains,
        "escape_vectors":    escape_vectors,
        "priority_matrix":   priority_matrix,
        "overall_risk":      _calc_overall_risk(phase1, phase2, escape_vectors),
        "executive_summary": _gen_executive_summary(phase1, phase2, attack_chains, escape_vectors),
    }


def _build_attack_chains(phase1: dict, phase2: dict) -> list[dict]:
    """构建 Top N 攻击链（最可利用的组合）。"""
    chains = []

    # 链 1: 已知 exploit CVE + 攻击工具
    exploit_vulns = [v for v in phase1.get("critical_vulns", []) if v.get("known_exploit")]
    if exploit_vulns and phase2.get("bin_audit", {}).get("found", {}).get("CRITICAL"):
        chains.append({
            "id":          "CHAIN-001",
            "name":        "远程代码执行 + 后渗透能力",
            "likelihood":  "HIGH",
            "impact":      "CRITICAL",
            "steps": [
                f"1. 利用 {exploit_vulns[0]['id']} 获得容器内代码执行",
                "2. 调用容器内已有工具（curl/nc/python）建立持久通道",
                "3. 内网横向移动或数据外泄",
            ],
            "cves": [v["id"] for v in exploit_vulns[:3]],
        })

    # 链 2: 密钥泄露 + 权限利用
    if phase1.get("secrets"):
        chains.append({
            "id":         "CHAIN-002",
            "name":       "密钥泄露 → 云/服务权限滥用",
            "likelihood": "CONFIRMED",
            "impact":     "HIGH",
            "steps": [
                f"1. 从镜像中提取硬编码凭证 ({phase1['secrets'][0]['category']})",
                "2. 使用凭证访问关联云服务/数据库/API",
                "3. 横向渗透至其他系统",
            ],
            "secrets": [s["title"] for s in phase1["secrets"][:3]],
        })

    # 链 3: root 运行 + 危险 capability
    if phase1.get("runs_as_root") and phase2.get("misconfigs"):
        chains.append({
            "id":         "CHAIN-003",
            "name":       "容器内提权 → 宿主机逃逸准备",
            "likelihood": "MEDIUM",
            "impact":     "CRITICAL",
            "steps": [
                "1. 容器以 root 运行，无需提权",
                "2. 利用 SUID 二进制或危险 capability 扩大权限",
                "3. 配合内核漏洞可实现容器逃逸",
            ],
        })

    # 链 4: 高危 CVE（无 PoC）+ 大量攻击工具
    high_fixable = [v for v in phase1.get("high_vulns", []) if v.get("has_fix")]
    bin_total = phase2.get("bin_audit", {}).get("total_dangerous", 0)
    if high_fixable and bin_total >= 3:
        chains.append({
            "id":         "CHAIN-004",
            "name":       "HIGH CVE + 丰富武器库 → 持续威胁",
            "likelihood": "MEDIUM",
            "impact":     "HIGH",
            "steps": [
                f"1. 利用 {len(high_fixable)} 个 HIGH CVE 之一获得初始访问",
                f"2. 镜像内包含 {bin_total} 个危险工具，攻击者可快速部署后门",
                "3. 利用内网连通性进行横向移动",
            ],
        })

    # 链 5: EOL 操作系统
    if phase1.get("image_eol", {}).get("is_eol"):
        chains.append({
            "id":         "CHAIN-005",
            "name":       "EOL 操作系统 → 持续漏洞供给",
            "likelihood": "HIGH",
            "impact":     "HIGH",
            "steps": [
                f"1. {phase1['image_eol']['reason']}",
                "2. 不再接收安全补丁，漏洞持续增加",
                "3. 攻击者可利用已公开但未修复的 N-day 漏洞",
            ],
        })

    return chains[:5]


def _assess_escape_vectors(phase1: dict, phase2: dict) -> list[dict]:
    """评估容器逃逸向量（静态分析）。"""
    vectors = []

    if phase1.get("runs_as_root"):
        vectors.append({
            "vector":   "ROOT_RUNNING",
            "severity": "HIGH",
            "desc":     "容器以 root 运行",
            "detail":   "配合内核 UAF/RCE 漏洞可直接逃逸到宿主机",
            "cis_ref":  "CIS-DI-0001 (DS-0002)",
        })

    for mc in phase2.get("misconfigs", []):
        mid = mc.get("id", "")
        if mid in ("DS-0002",) and mc.get("severity") in ("CRITICAL", "HIGH"):
            vectors.append({
                "vector":   f"MISCONFIG_{mid}",
                "severity": mc["severity"],
                "desc":     mc["title"],
                "detail":   mc.get("description", ""),
                "cis_ref":  mid,
            })

    kernel_cves = [v for v in phase2.get("all_vulns", [])
                   if v.get("target", "").lower() in ("", "linux")
                   and v.get("severity") == "CRITICAL"]
    if kernel_cves:
        vectors.append({
            "vector":   "KERNEL_CVE",
            "severity": "CRITICAL",
            "desc":     f"存在 {len(kernel_cves)} 个内核级 CRITICAL CVE",
            "detail":   f"代表: {kernel_cves[0]['vuln_id']} — {kernel_cves[0]['title']}",
            "cis_ref":  "",
        })

    return vectors


def _build_priority_matrix(phase1: dict, phase2: dict) -> list[dict]:
    """按可利用性优先级排列所有发现。"""
    items = []

    # P0: 密钥泄露（立即行动）
    for s in phase1.get("secrets", []):
        items.append({
            "priority": "P0",
            "type":     "SECRET",
            "id":       s.get("rule_id", ""),
            "title":    s.get("title", ""),
            "action":   "立即轮换所有暴露的凭证，从镜像层中彻底删除",
        })

    # P0: 已知 exploit CRITICAL CVE
    for v in phase1.get("critical_vulns", []):
        if v.get("known_exploit") and v.get("has_fix"):
            items.append({
                "priority": "P0",
                "type":     "CVE",
                "id":       v["id"],
                "title":    f"{v['pkg']} {v['version']} → {v['fix']}",
                "action":   f"立即升级 {v['pkg']} 到 {v['fix']}",
            })

    # P1: 有修复版本的 CRITICAL CVE
    for v in phase1.get("critical_vulns", []):
        if v.get("has_fix") and not v.get("known_exploit"):
            items.append({
                "priority": "P1",
                "type":     "CVE",
                "id":       v["id"],
                "title":    f"{v['pkg']} {v['version']} (CVSS {v.get('cvss','?')})",
                "action":   f"7天内升级 {v['pkg']} 到 {v['fix']}",
            })

    # P1: root 运行
    if phase1.get("runs_as_root"):
        items.append({
            "priority": "P1",
            "type":     "MISCONFIG",
            "id":       "DS-0002",
            "title":    "容器以 root 运行（CIS 4.1）",
            "action":   "在 Dockerfile 中添加 USER nonroot 指令",
        })

    # P2: 有修复版本的 HIGH CVE
    for v in phase1.get("high_vulns", [])[:5]:
        if v.get("has_fix"):
            items.append({
                "priority": "P2",
                "type":     "CVE",
                "id":       v["id"],
                "title":    f"{v['pkg']} {v['version']}",
                "action":   f"下次发布时升级 {v['pkg']} 到 {v['fix']}",
            })

    # P2: 危险二进制
    crit_bins = phase2.get("bin_audit", {}).get("found", {}).get("CRITICAL", [])
    if crit_bins:
        bin_names = [b["binary"] for b in crit_bins]
        items.append({
            "priority": "P2",
            "type":     "BINARY",
            "id":       "DANGEROUS-BINARY",
            "title":    f"高危工具存在于镜像中: {', '.join(bin_names[:4])}",
            "action":   "使用多阶段构建，生产镜像仅保留必要运行时文件",
        })

    return items[:20]


def _calc_overall_risk(phase1: dict, phase2: dict, escape_vectors: list) -> str:
    critical_escape = any(v["severity"] == "CRITICAL" for v in escape_vectors)
    if phase1.get("secrets") or critical_escape:
        return "CRITICAL"
    if phase1.get("p0_count", 0) > 0:
        return "CRITICAL"
    if phase1.get("p1_count", 0) >= 3 or phase1.get("runs_as_root"):
        return "HIGH"
    if phase1.get("p1_count", 0) > 0:
        return "HIGH"
    return "MEDIUM"


def _gen_executive_summary(phase1: dict, phase2: dict,
                            attack_chains: list, escape_vectors: list) -> str:
    overall = _calc_overall_risk(phase1, phase2, escape_vectors)
    parts = [
        f"整体风险等级: {overall}",
        f"发现 {phase1.get('p0_count',0)} 个 P0（立即行动）、"
        f"{phase1.get('p1_count',0)} 个 P1（7天内）发现",
    ]
    if phase1.get("secrets"):
        parts.append(f"⚠ 检测到 {len(phase1['secrets'])} 处密钥泄露，需立即轮换")
    if phase1.get("runs_as_root"):
        parts.append("⚠ 镜像以 root 运行，配合 CVE 可实现宿主机逃逸")
    if attack_chains:
        parts.append(f"识别出 {len(attack_chains)} 条攻击链，最高风险: {attack_chains[0]['name']}")
    bin_cap = phase2.get("bin_audit", {}).get("attack_capability", "")
    if bin_cap:
        parts.append(f"攻击者后渗透能力: {bin_cap}")
    return " | ".join(parts)


# ---------------------------------------------------------------------------
# 保存结果
# ---------------------------------------------------------------------------

def save_results(phase1: dict, phase2: dict, phase3: dict,
                 target: str, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    result = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "target":          target,
        "overall_risk":    phase3.get("overall_risk", "UNKNOWN"),
        "executive_summary": phase3.get("executive_summary", ""),
        "phase1": phase1,
        "phase2": {k: v for k, v in phase2.items() if k != "sbom_packages"},
        "phase3": phase3,
        "sbom_packages": phase2.get("sbom_packages", []),
    }
    out_file = output_dir / "audit_results.json"
    out_file.write_text(
        json.dumps(result, indent=2, ensure_ascii=False, default=str),
        encoding="utf-8",
    )
    return out_file


# ---------------------------------------------------------------------------
# Dockerfile 专项审计
# ---------------------------------------------------------------------------

def _run_dockerfile_audit(trivy_bin: str, dockerfile_path: str,
                          out_dir: Path, cache_dir: str | None) -> None:
    """对 Dockerfile 做静态安全审计：检测密钥/配置问题。"""
    import tempfile

    if os.path.isfile(dockerfile_path):
        tmpdir = tempfile.mkdtemp(prefix="trivy-df-")
        try:
            dest = os.path.join(tmpdir, "Dockerfile")
            import shutil
            shutil.copy2(dockerfile_path, dest)
            scan_dir = tmpdir
        except Exception:
            scan_dir = os.path.dirname(dockerfile_path)
    else:
        scan_dir = dockerfile_path
        tmpdir   = None

    print("  扫描 Dockerfile 密钥和 CIS 配置问题...")
    cmd = [trivy_bin, "config", "--format", "json", "--quiet", scan_dir]
    result = subprocess.run(cmd, capture_output=True, text=True)

    if tmpdir:
        import shutil
        shutil.rmtree(tmpdir, ignore_errors=True)

    misconfigs = []
    if result.stdout.strip():
        lines = result.stdout.strip().splitlines()
        start = next((i for i, l in enumerate(lines) if l.startswith("{")), None)
        if start is not None:
            try:
                data = json.loads("\n".join(lines[start:]))
                for target_r in data.get("Results", []):
                    for m in target_r.get("Misconfigurations", []) or []:
                        misconfigs.append({
                            "id":         m.get("ID", ""),
                            "title":      m.get("Title", ""),
                            "severity":   m.get("Severity", "UNKNOWN"),
                            "status":     m.get("Status", "FAIL"),
                            "resolution": m.get("Resolution", ""),
                            "description":m.get("Description", "")[:150],
                        })
            except Exception:
                pass

    # 检测 ENV 中的密钥模式
    secret_patterns = [
        (r'(?i)ENV\s+\w*(PASSWORD|PASSWD|PWD)\s*=\s*(\S+)', "密码"),
        (r'(?i)ENV\s+\w*(SECRET|TOKEN|KEY|API_KEY)\s*=\s*(\S+)', "密钥/Token"),
        (r'(?i)ENV\s+AWS_(?:SECRET|ACCESS)\S*\s*=\s*(\S+)', "AWS 凭证"),
        (r'(?i)ENV\s+\w*(PRIVATE_KEY|CERTIFICATE)\s*=\s*(\S+)', "证书/私钥"),
        (r'(?i)ARG\s+\w*(SECRET|TOKEN|PASSWORD|KEY)\s*=\s*(\S+)', "ARG 密钥"),
    ]
    secrets_found = []
    try:
        with open(os.path.join(scan_dir if not tmpdir else dockerfile_path),
                  errors="replace") as f:
            df_content = f.read()
    except Exception:
        df_content = ""

    for pattern, label in secret_patterns:
        for m in re.finditer(pattern, df_content):
            secrets_found.append({
                "pattern": label,
                "match":   m.group(0)[:80],
                "severity": "CRITICAL",
            })

    # 输出
    risk = "CRITICAL" if secrets_found else ("HIGH" if misconfigs else "LOW")
    print(f"\n{'='*62}")
    print(f" Dockerfile 静态审计完成")
    print(f"{'='*62}")
    print(f" 整体风险   : {risk}")
    print(f" 密钥泄露   : {len(secrets_found)} 处")
    print(f" 配置问题   : {len(misconfigs)} 处")

    if secrets_found:
        print("\n⚠️  检测到硬编码密钥（P0 — 立即修复）：")
        for s in secrets_found:
            print(f"   [{s['pattern']}] {s['match']}")

    if misconfigs:
        print("\n配置问题：")
        for m in misconfigs[:10]:
            sev_icon = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}.get(m["severity"],"⚪")
            print(f"   {sev_icon} [{m['severity']}] {m['id']} — {m['title']}")

    # 攻击链分析
    if secrets_found:
        print("\n🎯 攻击链分析：")
        for s in secrets_found[:2]:
            if "AWS" in s["pattern"]:
                print("  CHAIN-001: AWS 凭证泄露 → aws iam/s3 枚举 → 数据外泄/横向移动")
            elif "密码" in s["pattern"]:
                print("  CHAIN-002: 数据库密码泄露 → 直接数据库访问 → 数据窃取")
            else:
                print(f"  CHAIN-003: {s['pattern']}泄露 → 服务认证绕过 → 权限滥用")

    # 保存结果
    result_data = {
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "target":          dockerfile_path,
        "target_type":     "dockerfile",
        "overall_risk":    risk,
        "secrets_found":   secrets_found,
        "misconfigs":      misconfigs,
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    result_file = out_dir / "audit_results.json"
    result_file.write_text(json.dumps(result_data, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n 结果 JSON  : {result_file}")
    print(f"{'='*62}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="容器镜像安全审计（渗透测试视角）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    target_grp = parser.add_argument_group("审计目标（至少一个）")
    target_grp.add_argument("--image",      metavar="NAME:TAG", help="本地镜像名称")
    target_grp.add_argument("--input",      metavar="PATH",     help="本地 tar 归档路径")
    target_grp.add_argument("--dockerfile", metavar="PATH",     help="Dockerfile 文件或目录（静态分析密钥/配置）")

    parser.add_argument("--output-dir",    default="./audit-report", help="输出目录")
    parser.add_argument("--phase",
                        choices=["all", "quick", "deep", "exploit"],
                        default="all",
                        help="执行阶段（默认 all）")
    parser.add_argument("--with-layer-analysis", action="store_true",
                        help="包含层历史分析（需要 Docker）")
    parser.add_argument("--update-db",    action="store_true", help="联网更新漏洞库")
    parser.add_argument("--cache-dir",    metavar="PATH",   help="Trivy 缓存目录")
    parser.add_argument("--no-sbom",      action="store_true", help="跳过 SBOM 生成")
    args = parser.parse_args()

    if not args.image and not args.input and not args.dockerfile:
        parser.error("请指定 --image、--input 或 --dockerfile 中的至少一个")

    target   = args.image or args.input or args.dockerfile
    is_tar   = bool(args.input)
    out_dir  = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    trivy_bin = _find_trivy()
    if args.update_db:
        print("联网更新漏洞数据库...")
        update_db(trivy_bin, args.cache_dir)

    print(f"\n{'='*62}")
    print(f" 容器镜像安全审计  ─  渗透测试视角")
    print(f"{'='*62}")
    print(f" 目标   : {target}")
    print(f" 模式   : {'tar 归档' if is_tar else '本地镜像'}")
    print(f" 阶段   : {args.phase}")
    print(f" 扫描器 : Trivy {trivy_bin}")
    print(f" 时间   : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}")
    if args.dockerfile:
        print(f" Dockerfile: {args.dockerfile}")
    print(f"{'='*62}\n")

    # Dockerfile 模式：通过 trivy config 扫描静态问题
    if args.dockerfile and not args.image and not args.input:
        _run_dockerfile_audit(trivy_bin, args.dockerfile, out_dir, args.cache_dir)
        return

    # 执行各阶段
    phase1 = phase2 = phase3 = {}

    if args.phase in ("all", "quick"):
        phase1 = phase1_quick_triage(trivy_bin, target, is_tar, args.cache_dir)

        # 快速定性摘要
        qr = phase1.get("quick_rating", "?")
        print(f"\n  ┌─ Phase 1 快速定性结果 ──────────────────")
        print(f"  │  风险等级: {qr}")
        print(f"  │  CRITICAL CVE: {len(phase1.get('critical_vulns',[]))}  "
              f"HIGH: {len(phase1.get('high_vulns',[]))}")
        print(f"  │  密钥泄露: {len(phase1.get('secrets',[]))}")
        print(f"  │  root 运行: {'是 ⚠' if phase1.get('runs_as_root') else '否 ✓'}")
        if phase1.get("image_eol", {}).get("is_eol"):
            print(f"  │  EOL 警告: {phase1['image_eol']['reason']}")
        print(f"  └──────────────────────────────────────────\n")

        if args.phase == "quick":
            print("仅执行 Phase 1，生成快速报告...")
            phase2 = {"all_vulns": [], "misconfigs": [], "bin_audit": {"found": {}, "total_dangerous": 0, "attack_capability": ""}, "layer_analysis": {}, "vuln_counts": {}}
            phase3 = phase3_exploit_assessment(phase1, phase2, target)
            out_file = save_results(phase1, phase2, phase3, target, out_dir)
            print(f"\n快速审计 JSON: {out_file}")
            return

    if args.phase in ("all", "deep"):
        phase2 = phase2_deep_analysis(
            trivy_bin, target, is_tar, args.cache_dir,
            with_layer_analysis=args.with_layer_analysis,
            output_dir=out_dir,
        )
        vuln_c = phase2.get("vuln_counts", {})
        print(f"\n  ┌─ Phase 2 深度分析结果 ──────────────────")
        print(f"  │  CVE 总计: {sum(vuln_c.values())}  "
              f"CRITICAL={vuln_c.get('CRITICAL',0)} HIGH={vuln_c.get('HIGH',0)} "
              f"MEDIUM={vuln_c.get('MEDIUM',0)}")
        print(f"  │  配置问题: {len(phase2.get('misconfigs',[]))}")
        print(f"  │  危险二进制: {phase2.get('bin_audit',{}).get('total_dangerous',0)} 个")
        sbom = phase2.get("sbom_summary", {})
        if sbom.get("total_components"):
            print(f"  │  SBOM 组件: {sbom['total_components']} 个")
        print(f"  └──────────────────────────────────────────\n")

    if args.phase in ("all", "exploit"):
        phase3 = phase3_exploit_assessment(phase1, phase2, target)
        chains = phase3.get("attack_chains", [])
        print(f"\n  ┌─ Phase 3 利用评估结果 ──────────────────")
        print(f"  │  整体风险: {phase3.get('overall_risk','?')}")
        print(f"  │  攻击链数: {len(chains)}")
        for c in chains[:3]:
            print(f"  │    [{c.get('likelihood','?')}] {c['name']}")
        print(f"  └──────────────────────────────────────────\n")

    # 保存
    out_file = save_results(phase1, phase2, phase3, target, out_dir)

    print(f"\n{'='*62}")
    print(f" 审计完成")
    print(f"{'='*62}")
    print(f" 整体风险   : {phase3.get('overall_risk', phase1.get('quick_rating', '?'))}")
    print(f" 执行摘要   : {phase3.get('executive_summary', '')}")
    print(f" 结果 JSON  : {out_file}")
    print(f"\n生成报告: python3 scripts/generate_audit_report.py \\")
    print(f"           --audit-json {out_file} --output-dir {out_dir}")
    print(f"{'='*62}\n")


if __name__ == "__main__":
    main()
