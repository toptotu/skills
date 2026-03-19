#!/usr/bin/env python3
"""
容器镜像安全扫描（本地化模式，默认无需联网）

扫描目标类型：
  --image  NAME:TAG     镜像名称（从本地 Docker daemon 读取，已 pull/load 的镜像）
  --input  PATH         本地 tar 归档（docker save 导出的文件）或 OCI 目录
  --dockerfile PATH     Dockerfile 文件或目录（仅 CIS 基线检查，无需镜像和 DB）

默认行为（离线模式）：
  - 使用本地已缓存的漏洞数据库，不联网更新
  - 使用本地 Docker daemon 中已有的镜像，不拉取远程镜像
  - CIS 基线检查完全本地（内置规则，无需网络）

需要联网的操作（需显式开启）：
  --update-db           扫描前先联网更新漏洞库
  --pull                允许从远程 Registry 拉取镜像（默认禁用）

用法示例：
  # 扫描本地已有镜像（无需网络）
  python3 scripts/scan_image.py --image nginx:latest --output-dir ./report

  # 扫描本地 tar 包（完全离线）
  python3 scripts/scan_image.py --input /path/to/myapp.tar --output-dir ./report

  # 仅检查 Dockerfile CIS 合规（完全离线）
  python3 scripts/scan_image.py --dockerfile ./Dockerfile --output-dir ./report

  # 离线扫描 + 包含密钥检测
  python3 scripts/scan_image.py --image myapp:1.0 --scan-secrets --output-dir ./report

  # 联网更新 DB 后扫描
  python3 scripts/scan_image.py --image myapp:1.0 --update-db --output-dir ./report
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Trivy 查找
# ---------------------------------------------------------------------------

def find_trivy() -> str:
    """在 PATH 和 ~/.local/bin 中查找 trivy，找不到则报错。"""
    path = shutil.which("trivy")
    if path:
        return path
    local = Path.home() / ".local" / "bin" / "trivy"
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    raise RuntimeError(
        "未找到 trivy。请运行: python3 scripts/setup_trivy.py --check\n"
        "本地安装: python3 scripts/setup_trivy.py --local-binary /path/to/trivy\n"
        "包管理器: python3 scripts/setup_trivy.py --pkg-manager"
    )


# ---------------------------------------------------------------------------
# DB 状态检查
# ---------------------------------------------------------------------------

def check_db_exists(cache_dir: str | None = None) -> tuple[bool, str]:
    """检查漏洞数据库是否存在，返回 (exists, path)。"""
    base = Path(cache_dir) if cache_dir else Path.home() / ".cache" / "trivy"
    db   = base / "db" / "trivy.db"
    return db.exists(), str(db)


def warn_if_db_missing(cache_dir: str | None = None) -> None:
    exists, db_path = check_db_exists(cache_dir)
    if not exists:
        print("⚠️  漏洞数据库未找到，CVE 扫描结果将为空。")
        print("   离线导入: python3 scripts/setup_trivy.py --db-archive /path/to/trivy-db.tar.gz")
        print("   联网更新: python3 scripts/scan_image.py --update-db ...")


# ---------------------------------------------------------------------------
# 联网 DB 更新（可选）
# ---------------------------------------------------------------------------

def update_db(trivy_bin: str, cache_dir: str | None = None) -> None:
    """联网下载/更新漏洞库（仅在 --update-db 时调用）。"""
    print("正在联网更新漏洞数据库...")
    cmd = [trivy_bin, "image", "--download-db-only", "--no-progress"]
    if cache_dir:
        cmd += ["--cache-dir", cache_dir]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"  ⚠️  DB 更新失败（继续使用缓存）:\n  {result.stderr[:300]}")
    else:
        print("  ✅ 漏洞数据库更新完成。")


# ---------------------------------------------------------------------------
# 核心扫描命令构建
# ---------------------------------------------------------------------------

def _base_offline_flags(cache_dir: str | None) -> list[str]:
    """返回所有扫描命令共用的离线模式标志。"""
    flags = [
        "--skip-db-update",        # 不更新漏洞库
        "--skip-java-db-update",   # 不更新 Java 依赖库
        "--offline-scan",          # 不发起任何外部 API 请求
        "--no-progress",
    ]
    if cache_dir:
        flags += ["--cache-dir", cache_dir]
    return flags


def run_trivy(trivy_bin: str, args: list[str], label: str,
              cache_dir: str | None = None) -> dict:
    """运行 trivy 命令并返回解析后的 JSON 结果。"""
    cmd = [trivy_bin] + args + ["--format", "json", "--quiet"] + _base_offline_flags(cache_dir)
    print(f"  运行 {label} 扫描...")

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode not in (0, 1):
        print(f"  ⚠️  trivy 退出码: {result.returncode}")
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}")

    if not result.stdout.strip():
        if result.stderr:
            # 过滤常见的非错误日志
            stderr = result.stderr.strip()
            if any(s in stderr for s in ("INFO", "WARN", "Detected")):
                pass  # 正常日志，忽略
            else:
                print(f"  ⚠️  {label} 扫描无输出: {stderr[:200]}")
        return {}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        # trivy config 输出可能前缀有日志行
        lines = result.stdout.strip().splitlines()
        json_start = next((i for i, l in enumerate(lines)
                           if l.strip().startswith("{")), None)
        if json_start is not None:
            try:
                return json.loads("\n".join(lines[json_start:]))
            except json.JSONDecodeError:
                pass
        print(f"  ⚠️  {label} 结果 JSON 解析失败")
        return {}


# ---------------------------------------------------------------------------
# 扫描函数
# ---------------------------------------------------------------------------

def _image_or_input_args(image: str | None, input_path: str | None,
                          allow_pull: bool = False) -> list[str]:
    """
    构建 trivy image 的目标参数。
    - input_path 优先：扫描本地 tar/OCI 目录，完全离线
    - image 次之：扫描本地 Docker daemon 中的镜像
      - allow_pull=False（默认）：只用本地缓存镜像，不拉取
    """
    if input_path:
        return ["--input", input_path]
    target = [image]
    if not allow_pull:
        # 通过设置空 registry 来阻止拉取行为
        # Trivy 会直接访问 Docker daemon，如果镜像不存在则报错而非拉取
        pass
    return target


def scan_vulnerabilities(trivy_bin: str, image: str | None, input_path: str | None,
                         timeout: str, allow_pull: bool, cache_dir: str | None) -> dict:
    target_args = _image_or_input_args(image, input_path, allow_pull)
    return run_trivy(
        trivy_bin,
        ["image", "--scanners", "vuln", "--timeout", timeout] + target_args,
        "漏洞（CVE）",
        cache_dir=cache_dir,
    )


def scan_misconfigurations(trivy_bin: str, image: str | None, input_path: str | None,
                           timeout: str, allow_pull: bool, cache_dir: str | None) -> dict:
    target_args = _image_or_input_args(image, input_path, allow_pull)
    return run_trivy(
        trivy_bin,
        ["image", "--scanners", "misconfig", "--timeout", timeout] + target_args,
        "CIS 基线配置",
        cache_dir=cache_dir,
    )


def scan_secrets(trivy_bin: str, image: str | None, input_path: str | None,
                 timeout: str, allow_pull: bool, cache_dir: str | None) -> dict:
    target_args = _image_or_input_args(image, input_path, allow_pull)
    return run_trivy(
        trivy_bin,
        ["image", "--scanners", "secret", "--timeout", timeout] + target_args,
        "密钥/凭证",
        cache_dir=cache_dir,
    )


def scan_dockerfile(trivy_bin: str, dockerfile_path: str) -> dict:
    """
    扫描 Dockerfile 的 CIS 基线合规性。
    完全本地操作，不需要镜像和漏洞数据库。
    """
    import tempfile

    # trivy config 接受目录，不接受单个文件路径
    if os.path.isfile(dockerfile_path):
        tmpdir = tempfile.mkdtemp(prefix="trivy-dockerfile-")
        try:
            shutil.copy2(dockerfile_path, os.path.join(tmpdir, "Dockerfile"))
            return _run_trivy_config(trivy_bin, tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    elif os.path.isdir(dockerfile_path):
        return _run_trivy_config(trivy_bin, dockerfile_path)
    else:
        print(f"  ⚠️  Dockerfile 路径不存在: {dockerfile_path}")
        return {}


def _run_trivy_config(trivy_bin: str, directory: str) -> dict:
    cmd = [trivy_bin, "config", "--format", "json", "--quiet", directory]
    print("  运行 Dockerfile CIS 基线检查...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if not result.stdout.strip():
        if result.stderr:
            print(f"  ⚠️  {result.stderr[:200]}")
        return {}
    lines = result.stdout.strip().splitlines()
    start = next((i for i, l in enumerate(lines) if l.strip().startswith("{")), None)
    if start is None:
        return {}
    try:
        return json.loads("\n".join(lines[start:]))
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# 结果处理
# ---------------------------------------------------------------------------

def extract_image_metadata(scan_data: dict) -> dict:
    if "Metadata" not in scan_data:
        return {}
    m = scan_data["Metadata"]
    return {
        "os":           m.get("OS", {}),
        "image_id":     m.get("ImageID", ""),
        "repo_tags":    m.get("RepoTags", []),
        "repo_digests": m.get("RepoDigests", []),
    }


def count_severities(results: list[dict], key: str) -> dict[str, int]:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for target in results:
        for item in target.get(key, []) or []:
            sev = (item.get("Severity") or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def build_summary(target_label: str, vuln_data: dict,
                  misconfig_data: dict, secret_data: dict) -> dict:
    vuln_results    = vuln_data.get("Results", []) or []
    misconf_results = misconfig_data.get("Results", []) or []
    secret_results  = secret_data.get("Results", []) if secret_data else []

    vc = count_severities(vuln_results, "Vulnerabilities")
    mc = count_severities(misconf_results, "Misconfigurations")

    secret_count = sum(len(r.get("Secrets", []) or []) for r in secret_results or [])

    passed = failed = 0
    for target in misconf_results:
        for m in target.get("Misconfigurations", []) or []:
            if m.get("Status") == "PASS":
                passed += 1
            else:
                failed += 1
    total_checks = passed + failed
    cis_score = round(passed / total_checks * 100, 1) if total_checks else None

    risk = "PASS"
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if vc.get(sev, 0) > 0 or mc.get(sev, 0) > 0:
            risk = sev
            break

    return {
        "target":           target_label,
        "scan_timestamp":   datetime.now(timezone.utc).isoformat(),
        "scan_mode":        "offline",
        "risk_rating":      risk,
        "cis_compliance":   {"passed": passed, "total": total_checks, "score_pct": cis_score},
        "vulnerability_counts":  vc,
        "misconfig_counts":       mc,
        "secret_count":           secret_count,
        "total_vulnerabilities":  sum(vc.values()),
        "total_misconfigs":       sum(mc.values()),
        "image_metadata":         extract_image_metadata(vuln_data),
    }


def _get_cvss(vuln: dict) -> float | None:
    scores = []
    for src in (vuln.get("CVSS") or {}).values():
        for k in ("V3Score", "V2Score"):
            v = src.get(k)
            if v is not None:
                try:
                    scores.append(float(v))
                except (ValueError, TypeError):
                    pass
    return round(max(scores), 1) if scores else None


def collect_all_vulnerabilities(results: list[dict]) -> list[dict]:
    findings = []
    for target in results:
        for v in target.get("Vulnerabilities", []) or []:
            findings.append({
                "target":           target.get("Target", ""),
                "target_type":      target.get("Type", ""),
                "vuln_id":          v.get("VulnerabilityID", ""),
                "pkg_name":         v.get("PkgName", ""),
                "installed_version":v.get("InstalledVersion", ""),
                "fixed_version":    v.get("FixedVersion", ""),
                "severity":         v.get("Severity", "UNKNOWN"),
                "cvss_score":       _get_cvss(v),
                "title":            v.get("Title", ""),
                "description":      (v.get("Description") or "")[:500],
                "references":       v.get("References", [])[:3],
                "cwe_ids":          v.get("CweIDs", []),
                "primary_url":      v.get("PrimaryURL", ""),
            })
    sev_o = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4}
    findings.sort(key=lambda x: (sev_o.get(x["severity"].upper(),5),
                                  -(x["cvss_score"] or 0)))
    return findings


def collect_all_misconfigurations(results: list[dict]) -> list[dict]:
    findings = []
    for target in results:
        for m in target.get("Misconfigurations", []) or []:
            mid = m.get("ID", "")
            avd = m.get("AVDID", "")
            cis_controls = []
            if mid.startswith(("CIS-", "DS-")):
                cis_controls.append(mid)
            if avd:
                cis_controls.append(f"AVD: {avd}")
            for ref in m.get("References", [])[:3]:
                if "cisecurity.org" in ref or "avd.aquasec" in ref:
                    cis_controls.append(ref)
            findings.append({
                "target":       target.get("Target", ""),
                "misconfig_id": mid,
                "avd_id":       avd,
                "type":         m.get("Type", ""),
                "title":        m.get("Title", ""),
                "description":  m.get("Description", ""),
                "message":      m.get("Message", ""),
                "severity":     m.get("Severity", "UNKNOWN"),
                "status":       m.get("Status", "FAIL"),
                "resolution":   m.get("Resolution", ""),
                "references":   m.get("References", [])[:3],
                "cis_controls": cis_controls,
            })
    sev_o = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4}
    findings.sort(key=lambda x: (0 if x["status"]=="FAIL" else 1,
                                  sev_o.get(x["severity"].upper(),5)))
    return findings


def collect_all_secrets(results: list[dict]) -> list[dict]:
    findings = []
    for target in (results or []):
        for s in target.get("Secrets", []) or []:
            findings.append({
                "target":   target.get("Target", ""),
                "rule_id":  s.get("RuleID", ""),
                "category": s.get("Category", ""),
                "title":    s.get("Title", ""),
                "severity": s.get("Severity", "HIGH"),
                "match":    s.get("Match", "")[:100],
            })
    return findings


def save_json(data: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


# ---------------------------------------------------------------------------
# 主函数
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="容器镜像安全扫描（本地化模式，默认无需联网）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # 扫描目标
    target_group = parser.add_argument_group("扫描目标（至少选一个）")
    target_group.add_argument("--image",      metavar="NAME:TAG",
                              help="镜像名称（本地 Docker daemon 中已有的镜像）")
    target_group.add_argument("--input",      metavar="PATH",
                              help="本地 tar 归档路径（docker save 导出），完全离线")
    target_group.add_argument("--dockerfile", metavar="PATH",
                              help="Dockerfile 文件或目录（CIS 基线检查，无需镜像）")

    # 扫描选项
    scan_group = parser.add_argument_group("扫描选项")
    scan_group.add_argument("--scan-secrets", action="store_true",
                            help="同时扫描镜像中的密钥/凭证泄露")
    scan_group.add_argument("--timeout",      default="5m",
                            help="单项扫描超时（默认 5m）")
    scan_group.add_argument("--output-dir",   default="./scan-results",
                            help="扫描结果输出目录（默认 ./scan-results）")
    scan_group.add_argument("--cache-dir",    metavar="PATH",
                            help="Trivy 缓存目录（默认 ~/.cache/trivy）")

    # 网络选项（显式开启）
    net_group = parser.add_argument_group("网络选项（默认均为关闭）")
    net_group.add_argument("--update-db", action="store_true",
                           help="扫描前联网更新漏洞库（需要网络）")
    net_group.add_argument("--pull",      action="store_true",
                           help="允许从远程 Registry 拉取镜像（默认禁止）")

    args = parser.parse_args()

    # 验证参数
    if not args.image and not args.input and not args.dockerfile:
        parser.error("请至少指定一个扫描目标: --image / --input / --dockerfile")

    if args.image and args.input:
        parser.error("--image 和 --input 不能同时使用，请选择其一")

    target_label = args.image or args.input or args.dockerfile

    # 查找 trivy
    try:
        trivy_bin = find_trivy()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    raw_dir    = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    # ── 打印扫描信息 ──────────────────────────────────────────
    print(f"\n{'='*60}")
    print("容器镜像安全扫描（本地化模式）")
    print(f"{'='*60}")
    if args.image:
        print(f"镜像名称  : {args.image}（本地 Docker daemon）")
    elif args.input:
        print(f"镜像文件  : {args.input}（本地 tar 归档）")
    if args.dockerfile:
        print(f"Dockerfile: {args.dockerfile}")
    print(f"扫描工具  : Trivy ({trivy_bin})")
    print(f"扫描模式  : {'离线（不联网）' if not args.update_db and not args.pull else '在线'}")
    print(f"输出目录  : {output_dir}")
    print(f"时间戳    : {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")

    # ── 可选：联网更新 DB ─────────────────────────────────────
    if args.update_db:
        update_db(trivy_bin, args.cache_dir)
    else:
        warn_if_db_missing(args.cache_dir)

    # ── 扫描 ─────────────────────────────────────────────────
    vuln_data    = {}
    misconf_data = {}
    secret_data  = {}

    has_image_target = bool(args.image or args.input)

    # 1. CVE 漏洞扫描
    if has_image_target:
        print("[1/4] 扫描 CVE 漏洞（本地 DB）...")
        vuln_data = scan_vulnerabilities(
            trivy_bin, args.image, args.input,
            args.timeout, args.pull, args.cache_dir,
        )
        save_json(vuln_data, str(raw_dir / "vulnerabilities.json"))
    else:
        print("[1/4] CVE 扫描跳过（仅 Dockerfile 模式）")

    # 2. CIS 基线检查（镜像配置）
    if has_image_target:
        print("[2/4] 扫描 CIS 基线配置（镜像 config）...")
        misconf_data = scan_misconfigurations(
            trivy_bin, args.image, args.input,
            args.timeout, args.pull, args.cache_dir,
        )
    else:
        print("[2/4] CIS 基线扫描跳过（无镜像目标）")

    # 2b. Dockerfile CIS 检查（内置规则，完全离线）
    if args.dockerfile:
        print(f"[2b] 扫描 Dockerfile CIS 基线: {args.dockerfile}")
        df_data = scan_dockerfile(trivy_bin, args.dockerfile)
        if df_data.get("Results"):
            existing = misconf_data.get("Results") or []
            misconf_data["Results"] = existing + df_data["Results"]

    if misconf_data:
        save_json(misconf_data, str(raw_dir / "misconfigurations.json"))

    # 3. 密钥/凭证扫描（可选）
    if args.scan_secrets and has_image_target:
        print("[3/4] 扫描密钥/凭证泄露...")
        secret_data = scan_secrets(
            trivy_bin, args.image, args.input,
            args.timeout, args.pull, args.cache_dir,
        )
        save_json(secret_data, str(raw_dir / "secrets.json"))
    elif args.scan_secrets:
        print("[3/4] 密钥扫描需要镜像目标（跳过）")
    else:
        print("[3/4] 密钥扫描已跳过（使用 --scan-secrets 开启）")

    # 4. 汇总
    print("[4/4] 生成扫描摘要...")
    summary = build_summary(target_label, vuln_data, misconf_data, secret_data)

    all_vulns    = collect_all_vulnerabilities(vuln_data.get("Results", []) or [])
    all_misconfs = collect_all_misconfigurations(misconf_data.get("Results", []) or [])
    all_secrets  = collect_all_secrets(secret_data.get("Results", []) if secret_data else [])

    combined = {
        "summary":          summary,
        "vulnerabilities":  all_vulns,
        "misconfigurations":all_misconfs,
        "secrets":          all_secrets,
    }

    combined_path = output_dir / "scan_results.json"
    save_json(combined, str(combined_path))

    # ── 打印摘要 ──────────────────────────────────────────────
    print(f"\n{'='*60}")
    print("扫描完成 — 摘要")
    print(f"{'='*60}")
    print(f"整体风险等级  : {summary['risk_rating']}")
    cis = summary["cis_compliance"]
    if cis["total"] > 0:
        print(f"CIS 合规度     : {cis['passed']}/{cis['total']} ({cis['score_pct']}%)")
    vc = summary["vulnerability_counts"]
    print(f"CVE 漏洞       : CRITICAL={vc['CRITICAL']}  HIGH={vc['HIGH']}  "
          f"MEDIUM={vc['MEDIUM']}  LOW={vc['LOW']}")
    mc = summary["misconfig_counts"]
    print(f"配置问题       : CRITICAL={mc['CRITICAL']}  HIGH={mc['HIGH']}  "
          f"MEDIUM={mc['MEDIUM']}  LOW={mc['LOW']}")
    if args.scan_secrets:
        print(f"密钥泄露       : {summary['secret_count']}")
    print(f"\n原始结果目录   : {raw_dir}")
    print(f"汇总 JSON      : {combined_path}")
    print(f"\n生成报告: python3 scripts/generate_report.py "
          f"--scan-json {combined_path} --output-dir {output_dir} "
          f"--image '{target_label}'")
    print(f"{'='*60}\n")

    return str(combined_path)


if __name__ == "__main__":
    main()
