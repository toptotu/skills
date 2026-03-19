#!/usr/bin/env python3
"""
Go 开源项目安全公告抓取器
从多个权威数据源抓取最新 Go 项目安全漏洞数据：
  1. Go 官方漏洞库 (vuln.go.dev / osv.dev)
  2. OSV.dev API
  3. GitHub Security Advisories (需要 GitHub Token)
  4. NVD API v2

支持公司代理场景，自动读取 HTTPS_PROXY / HTTP_PROXY / GO_SECURITY_PROXY 环境变量。

用法:
    python3 scripts/fetch_advisories.py --days 1 --output-dir ./reports
    python3 scripts/fetch_advisories.py --proxy http://proxy.company.com:8080 --days 7
    python3 scripts/fetch_advisories.py --source goosv --repo kubernetes/kubernetes
    python3 scripts/fetch_advisories.py --help
"""

import argparse
import json
import os
import sys
import time
import urllib.parse
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests
import urllib3

# 添加 scripts 目录到 path
sys.path.insert(0, str(Path(__file__).parent))
from config import TrackerConfig, DEFAULT_TRACKED_REPOS

# 关闭不必要的 SSL 警告（仅在明确设置 verify=False 时）
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ---------------------------------------------------------------------------
# HTTP Session 工厂
# ---------------------------------------------------------------------------

def make_session(cfg: TrackerConfig, extra_headers: dict = None) -> requests.Session:
    """创建带有代理和认证的 requests Session。"""
    s = requests.Session()
    proxies = cfg.proxy.to_requests_proxies()
    if proxies:
        s.proxies.update(proxies)
    s.verify = cfg.proxy.to_requests_verify()
    s.headers.update({
        "User-Agent": "go-security-tracker/1.0 (security research)",
        "Accept": "application/json",
    })
    if extra_headers:
        s.headers.update(extra_headers)
    return s


def safe_get(session: requests.Session, url: str, params: dict = None,
             timeout: int = 30, retries: int = 3, verbose: bool = False) -> dict | list | None:
    """带重试的 GET 请求，返回 JSON 或 None。"""
    for attempt in range(retries):
        try:
            if verbose:
                print(f"    GET {url} params={params}")
            resp = session.get(url, params=params, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.ProxyError as e:
            print(f"    代理错误 [{url}]: {e}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
        except requests.exceptions.SSLError as e:
            print(f"    SSL错误 [{url}]: {e}")
            print("    提示: 设置 REQUESTS_CA_BUNDLE=/path/to/ca.pem 或使用 --no-verify-ssl")
            break
        except requests.exceptions.ConnectionError as e:
            print(f"    连接错误 [{url}] 第{attempt+1}次: {e}")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
        except requests.exceptions.Timeout:
            print(f"    超时 [{url}] 第{attempt+1}次")
            if attempt < retries - 1:
                time.sleep(2 ** attempt)
        except requests.exceptions.HTTPError as e:
            print(f"    HTTP错误 [{url}]: {e}")
            break
        except (json.JSONDecodeError, ValueError) as e:
            print(f"    JSON解析错误 [{url}]: {e}")
            break
    return None


# ---------------------------------------------------------------------------
# 数据源 1: Go 官方漏洞库 (vuln.go.dev → OSV 格式)
# ---------------------------------------------------------------------------

GO_OSV_BASE = "https://vuln.go.dev"
GO_OSV_INDEX = "https://vuln.go.dev/index/vulns.json"


def _fetch_go_osv_detail(session: requests.Session, vid: str, verbose: bool = False) -> dict | None:
    """抓取单条 Go 漏洞详情。URL 格式为 /ID/{id}.json，响应末尾可能追加 HTML，需要截取 JSON 部分。"""
    url = f"{GO_OSV_BASE}/ID/{vid}.json"
    for attempt in range(3):
        try:
            resp = session.get(url, timeout=20)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            text = resp.text.strip()
            # 响应末尾可能有 HTML 注释/标签，找到 JSON 结束位置
            json_end = text.rfind("}")
            if json_end == -1:
                return None
            json_text = text[:json_end + 1]
            return json.loads(json_text)
        except requests.exceptions.RequestException as e:
            if attempt < 2:
                time.sleep(2 ** attempt)
        except (json.JSONDecodeError, ValueError):
            pass
    return None


def fetch_go_osv(cfg: TrackerConfig, since: datetime, verbose: bool = False) -> list[dict]:
    """从 Go 官方漏洞库抓取最近的漏洞。"""
    session = make_session(cfg)
    print("  [1/4] 抓取 Go 官方漏洞库 (vuln.go.dev)...")

    index = safe_get(session, GO_OSV_INDEX, verbose=verbose)
    if not index:
        print("    ⚠ 无法获取 vuln.go.dev 索引，跳过")
        return []

    recent_ids = []
    for entry in index:
        modified = entry.get("modified") or entry.get("published", "")
        try:
            dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            if dt >= since:
                recent_ids.append(entry.get("id"))
        except (ValueError, AttributeError):
            pass

    print(f"    找到 {len(recent_ids)} 条最近更新的 Go 漏洞")
    vulns = []
    for vid in recent_ids[:100]:
        detail = _fetch_go_osv_detail(session, vid, verbose=verbose)
        if detail:
            detail["_source"] = "go-osv"
            vulns.append(detail)
        time.sleep(0.05)

    print(f"    成功获取 {len(vulns)} 条漏洞详情")
    return vulns


# ---------------------------------------------------------------------------
# 数据源 2: OSV.dev API (覆盖 Go 生态)
# ---------------------------------------------------------------------------

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"


def fetch_osv_batch(cfg: TrackerConfig, since: datetime, repos: list[str], verbose: bool = False) -> list[dict]:
    """从 OSV.dev 批量查询指定 Go 项目的漏洞。"""
    session = make_session(cfg)
    print("  [2/4] 抓取 OSV.dev 数据库...")

    # 将 GitHub repo 转换为 OSV ecosystem 查询格式
    # OSV Go 漏洞通过 package name 查询
    go_modules = _repos_to_go_modules(repos)

    all_vulns = []
    # 使用 OSV v1 query 查询每个模块
    for module in go_modules[:30]:  # 限制批量请求
        payload = {"package": {"name": module, "ecosystem": "Go"}}
        try:
            resp = session.post(
                "https://api.osv.dev/v1/query",
                json=payload,
                timeout=30,
            )
            if resp.status_code == 200:
                data = resp.json()
                for v in data.get("vulns", []):
                    # 过滤时间范围
                    modified = v.get("modified") or v.get("published", "")
                    try:
                        dt = datetime.fromisoformat(modified.replace("Z", "+00:00"))
                        if dt.tzinfo is None:
                            dt = dt.replace(tzinfo=timezone.utc)
                        if dt >= since:
                            v["_source"] = "osv"
                            all_vulns.append(v)
                    except (ValueError, AttributeError):
                        pass
        except requests.exceptions.RequestException as e:
            if verbose:
                print(f"    OSV query failed for {module}: {e}")
        time.sleep(0.05)

    # 去重
    seen = set()
    unique = []
    for v in all_vulns:
        vid = v.get("id", "")
        if vid not in seen:
            seen.add(vid)
            unique.append(v)

    print(f"    找到 {len(unique)} 条 OSV Go 漏洞（时间范围内）")
    return unique


def _repos_to_go_modules(repos: list[str]) -> list[str]:
    """将 GitHub repo 格式转换为 Go 模块路径。"""
    mapping = {
        "kubernetes/kubernetes": "k8s.io/kubernetes",
        "moby/moby": "github.com/docker/docker",
        "containerd/containerd": "github.com/containerd/containerd",
        "helm/helm": "helm.sh/helm/v3",
        "istio/istio": "istio.io/istio",
        "cilium/cilium": "github.com/cilium/cilium",
        "traefik/traefik": "github.com/traefik/traefik/v2",
        "etcd-io/etcd": "go.etcd.io/etcd/v3",
        "hashicorp/vault": "github.com/hashicorp/vault",
        "hashicorp/consul": "github.com/hashicorp/consul",
        "prometheus/prometheus": "github.com/prometheus/prometheus",
        "grafana/grafana": "github.com/grafana/grafana",
        "argoproj/argo-cd": "github.com/argoproj/argo-cd/v2",
        "go-gitea/gitea": "code.gitea.io/gitea",
        "grpc/grpc-go": "google.golang.org/grpc",
        "cert-manager/cert-manager": "github.com/cert-manager/cert-manager",
        "golang/go": "stdlib",
        "coredns/coredns": "github.com/coredns/coredns",
        "fluxcd/flux2": "github.com/fluxcd/flux2",
        "pingcap/tidb": "github.com/pingcap/tidb",
    }
    result = []
    for repo in repos:
        module = mapping.get(repo, f"github.com/{repo}")
        result.append(module)
    return result


# ---------------------------------------------------------------------------
# 数据源 3: GitHub Security Advisories (GraphQL)
# ---------------------------------------------------------------------------

GITHUB_GRAPHQL = "https://api.github.com/graphql"
GITHUB_REST_ADVISORIES = "https://api.github.com/advisories"


def fetch_github_advisories(cfg: TrackerConfig, since: datetime,
                             repos: list[str], verbose: bool = False) -> list[dict]:
    """从 GitHub Security Advisory Database 抓取 Go 漏洞。"""
    if not cfg.github_token:
        print("  [3/4] GitHub Token 未配置，使用 REST API（限速：60次/小时）...")
        return _fetch_github_rest(cfg, since, verbose)

    print("  [3/4] 抓取 GitHub Security Advisories (GraphQL)...")
    headers = {
        "Authorization": f"Bearer {cfg.github_token}",
        "Content-Type": "application/json",
    }
    session = make_session(cfg, extra_headers=headers)

    # 使用 REST API /advisories endpoint，过滤 Go 生态
    return _fetch_github_rest(cfg, since, verbose, session=session)


def _fetch_github_rest(cfg: TrackerConfig, since: datetime, verbose: bool = False,
                       session: requests.Session = None) -> list[dict]:
    """使用 GitHub REST API 抓取安全公告（无需 Token 但有限速）。"""
    if session is None:
        headers = {}
        if cfg.github_token:
            headers["Authorization"] = f"Bearer {cfg.github_token}"
        session = make_session(cfg, extra_headers=headers)

    advisories = []
    since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")

    # GitHub Global Security Advisories API，过滤 Go 生态
    params = {
        "ecosystem": "go",
        "per_page": 100,
        "updated_since": since_str,
        "sort": "updated",
        "direction": "desc",
    }

    page = 1
    while page <= 5:  # 最多抓取 5 页
        params["page"] = page
        data = safe_get(session, GITHUB_REST_ADVISORIES, params=params, verbose=verbose)
        if not data or not isinstance(data, list) or len(data) == 0:
            break
        for item in data:
            item["_source"] = "github-advisory"
        advisories.extend(data)
        if len(data) < 100:
            break
        page += 1
        time.sleep(0.5)

    print(f"    找到 {len(advisories)} 条 GitHub Go 安全公告")
    return advisories


# ---------------------------------------------------------------------------
# 数据源 4: NVD API v2
# ---------------------------------------------------------------------------

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd(cfg: TrackerConfig, since: datetime, verbose: bool = False) -> list[dict]:
    """从 NVD CVE 数据库抓取 Go 相关漏洞。"""
    print("  [4/4] 抓取 NVD CVE 数据库...")
    session = make_session(cfg)

    since_str = since.strftime("%Y-%m-%dT%H:%M:%S.000")
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")

    params = {
        "pubStartDate": since_str,
        "pubEndDate": now_str,
        "keywordSearch": "golang",
        "resultsPerPage": 100,
    }

    data = safe_get(session, NVD_BASE, params=params, timeout=60, verbose=verbose)
    if not data:
        print("    ⚠ NVD 请求失败，跳过")
        return []

    vulns = []
    for item in data.get("vulnerabilities", []):
        item["_source"] = "nvd"
        vulns.append(item)

    print(f"    找到 {len(vulns)} 条 NVD Go 相关 CVE")
    return vulns


# ---------------------------------------------------------------------------
# 数据规范化
# ---------------------------------------------------------------------------

SEVERITY_MAP = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "moderate": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "none": "INFO",
}


def normalize_advisory(raw: dict, source: str) -> dict:
    """将不同来源的漏洞数据规范化为统一格式。"""
    if source == "go-osv":
        return _normalize_osv(raw)
    elif source == "osv":
        return _normalize_osv(raw)
    elif source == "github-advisory":
        return _normalize_github(raw)
    elif source == "nvd":
        return _normalize_nvd(raw)
    return raw


def _normalize_osv(raw: dict) -> dict:
    """规范化 OSV/Go 官方漏洞库格式。"""
    aliases = raw.get("aliases", [])
    cve_id = next((a for a in aliases if a.startswith("CVE-")), None)
    ghsa_id = next((a for a in aliases if a.startswith("GHSA-")), None)

    # 提取严重度
    severity = "UNKNOWN"
    for s in raw.get("severity", []):
        score_str = s.get("score", "")
        stype = s.get("type", "")
        if "CVSS" in stype and score_str:
            try:
                score = float(score_str.split("/")[0]) if "/" not in score_str else _cvss_vector_to_score(score_str)
                severity = _score_to_severity(score)
            except (ValueError, IndexError):
                pass

    # 提取受影响包和修复版本
    affected = []
    for a in raw.get("affected", []):
        pkg = a.get("package", {})
        versions = []
        for r in a.get("ranges", []):
            for ev in r.get("events", []):
                if "fixed" in ev:
                    versions.append({"fixed": ev["fixed"]})
        affected.append({
            "package": pkg.get("name", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "fixed_versions": versions,
        })

    return {
        "id": raw.get("id", ""),
        "cve_id": cve_id,
        "ghsa_id": ghsa_id,
        "title": raw.get("summary", raw.get("id", "")),
        "description": raw.get("details", ""),
        "severity": severity,
        "published": raw.get("published", ""),
        "modified": raw.get("modified", ""),
        "affected": affected,
        "references": [r.get("url", "") for r in raw.get("references", [])],
        "source": raw.get("_source", "osv"),
        "_raw": raw,
    }


def _normalize_github(raw: dict) -> dict:
    """规范化 GitHub Security Advisory 格式。"""
    sev_raw = (raw.get("severity") or "").lower()
    severity = SEVERITY_MAP.get(sev_raw, "UNKNOWN")

    cvss_score = None
    for cvss in raw.get("cvss_severities", {}).values():
        if cvss and cvss.get("cvss_v3"):
            cvss_score = cvss["cvss_v3"].get("base_score")
            break

    affected = []
    for vuln_pkg in raw.get("vulnerabilities", []):
        pkg = vuln_pkg.get("package", {})
        affected.append({
            "package": pkg.get("name", ""),
            "ecosystem": pkg.get("ecosystem", ""),
            "vulnerable_version_range": vuln_pkg.get("vulnerable_version_range", ""),
            "fixed_at": vuln_pkg.get("first_patched_version", ""),
        })

    return {
        "id": raw.get("ghsa_id", ""),
        "cve_id": raw.get("cve_id"),
        "ghsa_id": raw.get("ghsa_id", ""),
        "title": raw.get("summary", ""),
        "description": raw.get("description", ""),
        "severity": severity,
        "cvss_score": cvss_score,
        "published": raw.get("published_at", ""),
        "modified": raw.get("updated_at", ""),
        "affected": affected,
        "references": [raw.get("html_url", "")] + [
            (r if isinstance(r, str) else r.get("url", "")) for r in raw.get("references", [])
        ],
        "cwes": [c.get("cwe_id") for c in raw.get("cwes", [])],
        "source": "github-advisory",
        "_raw": raw,
    }


def _normalize_nvd(raw: dict) -> dict:
    """规范化 NVD CVE 格式。"""
    cve = raw.get("cve", {})
    cve_id = cve.get("id", "")

    # 描述（取英文）
    desc = ""
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            desc = d.get("value", "")
            break

    # CVSS 评分
    severity = "UNKNOWN"
    cvss_score = None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for m in metrics.get(key, []):
            data = m.get("cvssData", {})
            cvss_score = data.get("baseScore")
            sev = data.get("baseSeverity", "")
            if sev:
                severity = sev.upper()
            elif cvss_score:
                severity = _score_to_severity(cvss_score)
            break
        if cvss_score:
            break

    # 受影响配置
    affected = []
    for config in cve.get("configurations", []):
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                cpe = match.get("criteria", "")
                if "golang" in cpe.lower() or ":go:" in cpe.lower():
                    affected.append({
                        "package": cpe,
                        "vulnerable": match.get("vulnerable", False),
                        "version_start": match.get("versionStartIncluding", ""),
                        "version_end": match.get("versionEndExcluding", ""),
                    })

    refs = [r.get("url", "") for r in cve.get("references", [])]

    return {
        "id": cve_id,
        "cve_id": cve_id,
        "ghsa_id": None,
        "title": desc[:100] if desc else cve_id,
        "description": desc,
        "severity": severity,
        "cvss_score": cvss_score,
        "published": cve.get("published", ""),
        "modified": cve.get("lastModified", ""),
        "affected": affected,
        "references": refs,
        "source": "nvd",
        "_raw": raw,
    }


def _score_to_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    elif score >= 7.0:
        return "HIGH"
    elif score >= 4.0:
        return "MEDIUM"
    elif score > 0:
        return "LOW"
    return "UNKNOWN"


def _cvss_vector_to_score(vector: str) -> float:
    """从 CVSS vector 字符串中提取 base score（不完整实现，仅提取已知格式）。"""
    # 例: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" -> 9.8
    # 这里采用简化方式，大多数情况下 OSV 已经提供了 score
    return 5.0  # 默认中等


# ---------------------------------------------------------------------------
# 漏洞分类（基于描述关键词）
# ---------------------------------------------------------------------------

def classify_vuln(vuln: dict) -> str:
    """
    使用加权置信度模型对漏洞分类（替换旧的简单关键词匹配）。
    支持自动识别新模式并分配 G-NEW-XXX 编号。
    """
    try:
        from pattern_analyzer import classify_with_confidence, register_new_pattern, _extract_new_pattern_name
        from datetime import datetime, timezone as _tz
        match = classify_with_confidence(vuln)
        if match.is_new:
            name_zh, name_en, keywords = _extract_new_pattern_name(vuln)
            desc = (vuln.get("description") or "")[:200]
            date_str = datetime.now(_tz.utc).strftime("%Y-%m-%d")
            return register_new_pattern(vuln, name_zh, name_en, keywords, desc, date_str)
        return match.pattern_id
    except Exception:
        # 降级到旧的简单匹配
        _CATEGORY_KEYWORDS_FALLBACK = {
            "G-INJ":    ["injection","sql","command injection","template injection","ldap"],
            "G-AUTH":   ["authentication","authorization","bypass","privilege","rbac","jwt","token"],
            "G-DOS":    ["denial of service","resource exhaustion","infinite loop","goroutine leak"],
            "G-MEM":    ["buffer overflow","use after free","out of bounds","unsafe.pointer"],
            "G-PROTO":  ["protobuf","yaml","deserialization","parsing"],
            "G-CRYPTO": ["cryptographic","certificate","tls","insecureskipverify","weak randomness"],
            "G-SSRF":   ["ssrf","server-side request forgery","open redirect"],
            "G-PATH":   ["path traversal","directory traversal","symlink","zip slip"],
            "G-RACE":   ["race condition","data race","toctou"],
            "G-SUPPLY": ["supply chain","typosquatting","malicious package"],
        }
        text = (vuln.get("title","") + " " + vuln.get("description","")).lower()
        for cat, kws in _CATEGORY_KEYWORDS_FALLBACK.items():
            for kw in kws:
                if kw in text:
                    return cat
        return "G-OTHER"


# ---------------------------------------------------------------------------
# 主抓取逻辑
# ---------------------------------------------------------------------------

def fetch_all(cfg: TrackerConfig, days: int, sources: list[str],
              repos: list[str], verbose: bool = False,
              fetch_patches: bool = True, max_patches: int = 25,
              date_str: str = "") -> list[dict]:
    """
    从所有指定数据源抓取漏洞，去重规范化后进行：
    1. 跨数据源严重度补全
    2. 模式分类（加权置信度 + 新模式自动识别）
    3. 代码补丁抓取（高危漏洞优先）
    4. 结构化特征提取
    """
    since = datetime.now(timezone.utc) - timedelta(days=days)
    print(f"\n抓取时间范围: {since.strftime('%Y-%m-%d %H:%M UTC')} 至今（最近 {days} 天）")
    print(f"追踪项目数: {len(repos)}\n")

    all_raw = []

    if "goosv" in sources or "all" in sources:
        try:
            raw = fetch_go_osv(cfg, since, verbose=verbose)
            all_raw.extend(raw)
        except Exception as e:
            print(f"    ⚠ Go OSV 抓取失败: {e}")

    if "osv" in sources or "all" in sources:
        try:
            raw = fetch_osv_batch(cfg, since, repos, verbose=verbose)
            all_raw.extend(raw)
        except Exception as e:
            print(f"    ⚠ OSV.dev 抓取失败: {e}")

    if "github" in sources or "all" in sources:
        try:
            raw = fetch_github_advisories(cfg, since, repos, verbose=verbose)
            all_raw.extend(raw)
        except Exception as e:
            print(f"    ⚠ GitHub Advisory 抓取失败: {e}")

    if "nvd" in sources or "all" in sources:
        try:
            raw = fetch_nvd(cfg, since, verbose=verbose)
            all_raw.extend(raw)
        except Exception as e:
            print(f"    ⚠ NVD 抓取失败: {e}")

    # 规范化 + 去重
    normalized = []
    seen_ids = set()
    for raw in all_raw:
        source = raw.get("_source", "unknown")
        norm = normalize_advisory(raw, source)
        vid = norm.get("id") or norm.get("cve_id") or norm.get("ghsa_id")
        if vid and vid in seen_ids:
            continue
        if vid:
            seen_ids.add(vid)
        normalized.append(norm)

    # 跨数据源严重度补全
    _enrich_severity_cross_source(normalized)

    # 模式分类（加权置信度 + 新模式自动识别）
    print("\n  [分析] 漏洞模式分类（加权置信度模型）...")
    for norm in normalized:
        norm["category"] = classify_vuln(norm)

    # 代码补丁抓取（CRITICAL/HIGH 优先）
    patches: dict = {}
    if fetch_patches and max_patches > 0:
        try:
            from fetch_patch import batch_fetch_patches
            patch_session = make_session(cfg)
            if cfg.github_token:
                patch_session.headers["Authorization"] = f"Bearer {cfg.github_token}"
            print(f"  [补丁] 抓取代码修改对比（最多 {max_patches} 条）...")
            patches = batch_fetch_patches(
                normalized, patch_session,
                max_fetch=max_patches, verbose=verbose,
            )
            fetched_cnt = sum(1 for p in patches.values() if p.go_diffs)
            print(f"         成功获取 {fetched_cnt} 条 Go 代码 diff")
        except Exception as e:
            if verbose:
                print(f"  [补丁] 抓取失败（跳过）: {e}")

    # 结构化特征提取（漏洞模式 + 代码对比）
    _date = date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    try:
        # 确保 scripts/ 目录在 sys.path 中
        import sys as _sys
        _scripts_dir = str(Path(__file__).parent)
        if _scripts_dir not in _sys.path:
            _sys.path.insert(0, _scripts_dir)
        from pattern_analyzer import analyze_all as _analyze_all
        normalized = _analyze_all(normalized, patches, _date)
    except Exception as e:
        print(f"  [分析] 特征提取模块加载失败: {type(e).__name__}: {e}")
        print(f"         将使用空特征（漏洞分类仍有效）")
        # 降级：从模式库生成基础特征
        try:
            from pattern_analyzer import (
                PATTERN_VULN_FEATURES, PATTERN_DEFENSE_POINTS,
                _extract_trigger_conditions, _pattern_display_name,
            )
            for n in normalized:
                cat = n.get("category", "G-OTHER")
                n["characteristics"] = {
                    "pattern_id":   cat,
                    "pattern_name": _pattern_display_name(cat),
                    "is_new_pattern": cat.startswith("G-NEW-"),
                    "vuln_features": PATTERN_VULN_FEATURES.get(cat, [])[:3],
                    "before_code":   "",
                    "after_code":    "",
                    "diff_filename": "",
                    "defense_points": PATTERN_DEFENSE_POINTS.get(cat, [])[:3],
                    "trigger_conditions": _extract_trigger_conditions(n),
                    "new_pattern_keywords": [],
                    "new_pattern_description": "",
                }
        except Exception as e2:
            for n in normalized:
                if "characteristics" not in n:
                    n["characteristics"] = {}

    # 按严重度排序
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}
    normalized.sort(key=lambda x: (sev_order.get(x.get("severity", "UNKNOWN"), 5),
                                   x.get("modified", "")), reverse=False)

    return normalized


def _enrich_severity_cross_source(vulns: list[dict]) -> None:
    """跨数据源严重度补全：通过 CVE/GHSA 别名将有 CVSS 的条目严重度传递给无 CVSS 的同条目。"""
    # 构建 CVE/GHSA -> severity 映射（只使用有具体严重度的条目）
    cve_to_sev: dict[str, str] = {}
    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        if sev == "UNKNOWN":
            continue
        for alias_key in ("cve_id", "ghsa_id"):
            alias = v.get(alias_key)
            if alias and alias not in cve_to_sev:
                cve_to_sev[alias] = sev
        # 也检查 _raw 中的 aliases 列表
        for alias in (v.get("_raw", {}).get("aliases", []) or []):
            if alias and alias not in cve_to_sev:
                cve_to_sev[alias] = sev

    # 补全 UNKNOWN 严重度
    for v in vulns:
        if v.get("severity") != "UNKNOWN":
            continue
        # 检查此条目的别名是否在映射中
        for alias_key in ("cve_id", "ghsa_id"):
            alias = v.get(alias_key)
            if alias and alias in cve_to_sev:
                v["severity"] = cve_to_sev[alias]
                break
        if v.get("severity") != "UNKNOWN":
            continue
        for alias in (v.get("_raw", {}).get("aliases", []) or []):
            if alias in cve_to_sev:
                v["severity"] = cve_to_sev[alias]
                break


def save_results(vulns: list[dict], output_dir: Path, date_str: str) -> Path:
    """保存抓取结果到 JSON 文件。"""
    raw_dir = output_dir / "raw" / date_str
    raw_dir.mkdir(parents=True, exist_ok=True)
    out_file = raw_dir / "advisories.json"

    payload = {
        "fetch_timestamp": datetime.now(timezone.utc).isoformat(),
        "date": date_str,
        "total": len(vulns),
        "severity_counts": _count_severities(vulns),
        "category_counts": _count_categories(vulns),
        "advisories": vulns,
    }

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False, default=str)

    return out_file


def _count_severities(vulns: list[dict]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for v in vulns:
        sev = v.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _count_categories(vulns: list[dict]) -> dict:
    counts = {}
    for v in vulns:
        cat = v.get("category", "G-OTHER")
        counts[cat] = counts.get(cat, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="抓取 Go 开源项目安全公告（支持企业代理）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python3 scripts/fetch_advisories.py --days 1
  python3 scripts/fetch_advisories.py --days 7 --source github
  python3 scripts/fetch_advisories.py --proxy http://proxy.company.com:8080
  python3 scripts/fetch_advisories.py --repo kubernetes/kubernetes --repo helm/helm
  python3 scripts/fetch_advisories.py --offline
        """,
    )
    parser.add_argument("--days", type=int, default=1, help="抓取最近 N 天（默认 1）")
    parser.add_argument("--output-dir", default="./go-security-reports", help="输出目录")
    parser.add_argument(
        "--source",
        choices=["all", "goosv", "osv", "github", "nvd"],
        default="all",
        help="数据源（默认 all）",
    )
    parser.add_argument(
        "--repo",
        action="append",
        dest="repos",
        metavar="OWNER/REPO",
        help="指定追踪的仓库（可多次使用），不指定则使用默认列表",
    )
    parser.add_argument("--proxy", help="代理地址（覆盖环境变量），例: http://proxy.company.com:8080")
    parser.add_argument("--no-verify-ssl", action="store_true", help="跳过 SSL 证书验证（不推荐生产使用）")
    parser.add_argument("--offline", action="store_true", help="离线模式，使用最新本地缓存")
    parser.add_argument("--verbose", "-v", action="store_true", help="详细输出")
    parser.add_argument("--date", help="指定日期（格式 YYYY-MM-DD），默认今天")
    parser.add_argument("--no-patch", action="store_true",
                        help="跳过代码补丁抓取（更快，但报告无代码对比）")
    parser.add_argument("--max-patches", type=int, default=25,
                        help="最多抓取补丁的漏洞数量（默认 25）")
    args = parser.parse_args()

    # 加载配置
    cfg = TrackerConfig.load(override_proxy=args.proxy)
    if args.no_verify_ssl:
        cfg.proxy.verify_ssl = False
        print("⚠ SSL 证书验证已禁用")

    repos = args.repos or cfg.tracked_repos
    output_dir = Path(args.output_dir)
    date_str = args.date or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    # 离线模式
    if args.offline:
        cached = output_dir / "raw" / date_str / "advisories.json"
        if cached.exists():
            print(f"离线模式: 使用缓存 {cached}")
            with open(cached, encoding="utf-8") as f:
                data = json.load(f)
            vulns = data.get("advisories", [])
            print(f"已加载 {len(vulns)} 条缓存漏洞")
            return str(cached)
        else:
            print(f"⚠ 未找到缓存文件 {cached}")
            sys.exit(1)

    # 打印代理配置（调试用）
    proxy_cfg = cfg.proxy
    if proxy_cfg.https_proxy or proxy_cfg.http_proxy:
        print(f"代理配置: HTTPS={proxy_cfg.https_proxy} HTTP={proxy_cfg.http_proxy}")
        print(f"SSL验证: {proxy_cfg.verify_ssl}")
    else:
        print("代理配置: 未使用代理（直连）")

    print(f"\n{'='*60}")
    print(f"Go 开源项目安全公告抓取")
    print(f"{'='*60}")
    print(f"日期: {date_str}")
    print(f"数据源: {args.source}")
    print(f"时间范围: 最近 {args.days} 天")
    print(f"{'='*60}")

    sources = [args.source] if args.source != "all" else ["all"]
    vulns = fetch_all(
        cfg, args.days, sources, repos,
        verbose=args.verbose,
        fetch_patches=not args.no_patch,
        max_patches=args.max_patches,
        date_str=date_str,
    )

    out_file = save_results(vulns, output_dir, date_str)

    # 打印摘要
    sev_counts = _count_severities(vulns)
    cat_counts = _count_categories(vulns)
    print(f"\n{'='*60}")
    print(f"抓取完成 — 共 {len(vulns)} 条漏洞")
    print(f"{'='*60}")
    print(f"严重度分布: CRITICAL={sev_counts['CRITICAL']} HIGH={sev_counts['HIGH']} "
          f"MEDIUM={sev_counts['MEDIUM']} LOW={sev_counts['LOW']}")
    if cat_counts:
        top_cats = sorted(cat_counts.items(), key=lambda x: -x[1])[:3]
        print(f"主要类型: {', '.join(f'{k}({v})' for k, v in top_cats)}")
    print(f"\n原始数据已保存: {out_file}")
    print(f"\n下一步: python3 scripts/generate_digest.py --raw-file {out_file} "
          f"--output-dir {output_dir} --image '{date_str}'")
    print(f"{'='*60}\n")

    return str(out_file)


if __name__ == "__main__":
    main()
