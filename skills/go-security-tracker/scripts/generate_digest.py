#!/usr/bin/env python3
"""
Go 安全日报生成器
从 fetch_advisories.py 的输出 JSON 生成 HTML 和 Markdown 格式的安全日报。
日报包含漏洞详情、特征分析、防御建议和代码 review 重点。

用法:
    python3 scripts/generate_digest.py --raw-file ./reports/raw/2025-01-01/advisories.json \\
        --output-dir ./reports --format both
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import VULN_CATEGORIES, TrackerConfig


# ---------------------------------------------------------------------------
# 颜色/样式常量
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#b71c1c",
    "HIGH":     "#e65100",
    "MEDIUM":   "#f57f17",
    "LOW":      "#1b5e20",
    "UNKNOWN":  "#546e7a",
    "INFO":     "#0277bd",
}

CATEGORY_COLORS = {
    "G-INJ":    "#880e4f",
    "G-AUTH":   "#1a237e",
    "G-DOS":    "#b71c1c",
    "G-MEM":    "#4a148c",
    "G-PROTO":  "#006064",
    "G-CRYPTO": "#1b5e20",
    "G-SSRF":   "#e65100",
    "G-PATH":   "#33691e",
    "G-RACE":   "#bf360c",
    "G-SUPPLY": "#212121",
    "G-OTHER":  "#546e7a",
}

SEVERITY_ICONS = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "UNKNOWN":  "⚪",
}

# 漏洞类型 -> 防御建议模板
DEFENSE_TEMPLATES = {
    "G-INJ": """
- 使用参数化查询，禁止字符串拼接 SQL/命令
- 对所有外部输入进行严格类型验证和白名单过滤
- 使用 `html/template` 而非 `text/template` 处理 HTML 输出
- 对命令执行使用 `exec.Command` 明确参数数组而非 shell 字符串
""",
    "G-AUTH": """
- 验证所有 JWT/Token 的签名算法，拒绝 `alg:none`
- 使用最小权限原则，RBAC 策略严格审计
- 认证和授权逻辑分离，避免在业务代码中内联权限检查
- 使用 `crypto/subtle.ConstantTimeCompare` 比较敏感字节串
""",
    "G-DOS": """
- 为所有 HTTP handler 设置 `http.TimeoutHandler` 和请求体大小限制
- 避免在循环中无界分配内存；使用 `sync.Pool` 复用对象
- 正则表达式使用 `regexp/syntax` 检查是否存在指数回溯
- 对 goroutine 数量设置上限，使用 worker pool 模式
- 开启 `net/http` 的 `MaxHeaderBytes` 和 `ReadHeaderTimeout`
""",
    "G-MEM": """
- 最小化 `unsafe` 包的使用范围，所有 `unsafe.Pointer` 操作必须 review
- cgo 边界处验证所有指针和长度，不信任 C 端数据
- 使用 `-race` 标志和模糊测试 (`go-fuzz`/`go test -fuzz`) 检测内存问题
""",
    "G-PROTO": """
- 对 Protobuf/JSON 消息设置最大大小限制，防止"解析炸弹"
- YAML 反序列化时使用 `gopkg.in/yaml.v3` 并禁用 `!!python/object` 类型
- 对所有反序列化结果进行二次验证，不信任来自网络的结构体字段
""",
    "G-CRYPTO": """
- 使用 `crypto/rand` 而非 `math/rand` 生成密钥和 nonce
- TLS 配置强制 `MinVersion: tls.VersionTLS12`，禁用弱 cipher suite
- 证书校验时不要设置 `InsecureSkipVerify: true`
- 使用 `x509.Certificate.VerifyHostname` 或标准 TLS 握手
""",
    "G-SSRF": """
- 对 `http.Client` 设置自定义 `Transport`，过滤内网 IP 段（RFC 1918/loopback）
- 白名单限制允许请求的目标域名
- 设置重定向策略，防止跳转到内网地址：`CheckRedirect: func(...) error { return http.ErrUseLastResponse }`
""",
    "G-PATH": """
- 使用 `filepath.Clean` + `filepath.Rel` 验证路径是否仍在预期目录内
- 避免直接使用用户输入拼接文件路径
- 使用 `os.OpenRoot`（Go 1.24+）或 `filepath.EvalSymlinks` 解析符号链接
""",
    "G-RACE": """
- 使用 `-race` 进行 CI 测试，定期运行竞争检测
- map 读写使用 `sync.RWMutex` 或 `sync.Map`
- 状态更新使用 `sync/atomic` 原子操作
- 避免 TOCTOU：检查和使用操作之间不能被中断，用锁保护
""",
    "G-SUPPLY": """
- 启用 `go.sum` 校验，使用私有 GOPROXY 镜像
- 定期运行 `govulncheck ./...` 扫描已知漏洞
- 在 CI 中集成 Dependabot/Renovate 自动更新依赖
- 审计第三方包的 import 路径，防止 typosquatting
""",
    "G-OTHER": """
- 参考 OWASP Go Security Cheat Sheet 进行全面审计
- 定期使用 `gosec`, `staticcheck`, `govulncheck` 进行静态分析
""",
}


# ---------------------------------------------------------------------------
# 数据加载
# ---------------------------------------------------------------------------

def load_raw(raw_file: str) -> dict:
    with open(raw_file, encoding="utf-8") as f:
        return json.load(f)


# ---------------------------------------------------------------------------
# Markdown 日报
# ---------------------------------------------------------------------------

def generate_markdown(data: dict, date_str: str) -> str:
    advisories = data.get("advisories", [])
    sev_counts = data.get("severity_counts", {})
    cat_counts = data.get("category_counts", {})
    total = data.get("total", len(advisories))

    lines = []

    # 标题
    lines += [
        f"# Go 开源项目安全日报 — {date_str}",
        "",
        f"> 生成时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"> 数据来源: Go 官方漏洞库 / OSV.dev / GitHub Security Advisories / NVD  ",
        f"> 覆盖项目: kubernetes, docker, etcd, helm, vault, prometheus, grafana 等 25+ 个知名 Go 项目",
        "",
        "---",
        "",
    ]

    # 执行摘要
    risk_icon = "🔴" if sev_counts.get("CRITICAL", 0) > 0 else \
                "🟠" if sev_counts.get("HIGH", 0) > 0 else \
                "🟡" if sev_counts.get("MEDIUM", 0) > 0 else "🟢"

    lines += [
        "## 执行摘要",
        "",
        f"| 指标 | 数值 |",
        f"|------|------|",
        f"| **今日新增漏洞** | {total} |",
        f"| **整体风险等级** | {risk_icon} {'CRITICAL' if sev_counts.get('CRITICAL',0)>0 else 'HIGH' if sev_counts.get('HIGH',0)>0 else 'MEDIUM' if sev_counts.get('MEDIUM',0)>0 else 'LOW'} |",
        f"| 🔴 CRITICAL | {sev_counts.get('CRITICAL', 0)} |",
        f"| 🟠 HIGH | {sev_counts.get('HIGH', 0)} |",
        f"| 🟡 MEDIUM | {sev_counts.get('MEDIUM', 0)} |",
        f"| 🟢 LOW | {sev_counts.get('LOW', 0)} |",
        "",
    ]

    # 高危漏洞速览
    critical_high = [v for v in advisories if v.get("severity") in ("CRITICAL", "HIGH")]
    if critical_high:
        lines += [
            "### ⚠️ 高危漏洞速览",
            "",
            "| 编号 | 项目/包 | 严重度 | 类型 | 摘要 |",
            "|------|---------|--------|------|------|",
        ]
        for v in critical_high[:10]:
            vid = v.get("id") or v.get("cve_id") or v.get("ghsa_id") or "N/A"
            pkg = _get_package_name(v)
            sev = v.get("severity", "UNKNOWN")
            cat = v.get("category", "G-OTHER")
            cat_label = VULN_CATEGORIES.get(cat, cat)
            title = (v.get("title") or "")[:60]
            lines.append(f"| `{vid}` | `{pkg}` | {SEVERITY_ICONS.get(sev,'')} {sev} | {cat_label} | {title} |")
        lines.append("")

    lines.append("---")
    lines.append("")

    # 漏洞详情
    lines += ["## 漏洞详情", ""]

    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        group = [v for v in advisories if v.get("severity") == sev]
        if not group:
            continue
        lines += [
            f"### {SEVERITY_ICONS.get(sev, '')} {sev} （{len(group)} 条）",
            "",
        ]
        for v in group:
            vid = v.get("id") or v.get("cve_id") or v.get("ghsa_id") or "N/A"
            cve = v.get("cve_id", "")
            ghsa = v.get("ghsa_id", "")
            pkg = _get_package_name(v)
            fix = _get_fix_version(v)
            cat = VULN_CATEGORIES.get(v.get("category", "G-OTHER"), "其他")
            desc = (v.get("description") or "暂无描述")[:400]
            refs = v.get("references", [])
            ref_links = " / ".join(f"[链接]({r})" for r in refs[:3] if r)
            cwes = v.get("cwes", [])
            cvss = v.get("cvss_score")

            lines += [
                f"#### `{vid}`",
                "",
                f"- **类型**: {cat}",
                f"- **受影响包**: `{pkg}`",
            ]
            if cve and cve != vid:
                lines.append(f"- **CVE**: `{cve}`")
            if ghsa and ghsa != vid:
                lines.append(f"- **GHSA**: `{ghsa}`")
            if cvss:
                lines.append(f"- **CVSS 评分**: {cvss}")
            if cwes:
                lines.append(f"- **CWE**: {', '.join(cwes)}")
            lines += [
                f"- **修复版本**: {fix or '请关注项目发布页'}",
                f"- **漏洞描述**: {desc}",
            ]
            if ref_links:
                lines.append(f"- **参考链接**: {ref_links}")
            lines.append("")

    lines.append("---")
    lines.append("")

    # 漏洞特征分析
    lines += ["## 漏洞特征分析", ""]

    if cat_counts:
        lines += [
            "### 本期漏洞类型分布",
            "",
            "| 类型 | 数量 | 说明 |",
            "|------|------|------|",
        ]
        for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1]):
            label = VULN_CATEGORIES.get(cat, cat)
            lines.append(f"| {cat} | {count} | {label} |")
        lines.append("")

    # 主要漏洞模式
    dominant_cats = [cat for cat, _ in sorted(cat_counts.items(), key=lambda x: -x[1])[:3]] if cat_counts else []
    if dominant_cats:
        lines += [
            "### 主要漏洞模式",
            "",
        ]
        for cat in dominant_cats:
            label = VULN_CATEGORIES.get(cat, cat)
            count = cat_counts.get(cat, 0)
            lines += [
                f"**{cat} — {label}**（本期 {count} 条）",
                "",
                _get_pattern_summary(cat),
                "",
            ]

    lines.append("---")
    lines.append("")

    # 防御建议
    lines += ["## 防御建议", ""]

    if dominant_cats:
        lines += [
            "### 针对本期漏洞的加固措施",
            "",
        ]
        for cat in dominant_cats:
            label = VULN_CATEGORIES.get(cat, cat)
            defense = DEFENSE_TEMPLATES.get(cat, DEFENSE_TEMPLATES["G-OTHER"]).strip()
            lines += [
                f"#### {cat} — {label}",
                "",
                defense,
                "",
            ]

    lines += [
        "### 通用 Go 安全加固 Checklist",
        "",
        "- [ ] 运行 `govulncheck ./...` 检查已知漏洞",
        "- [ ] CI 中启用 `-race` 标志",
        "- [ ] 审计 `unsafe` 包使用位置",
        "- [ ] 检查所有 HTTP handler 的超时和大小限制",
        "- [ ] 验证 TLS 配置（MinVersion, cipher suites）",
        "- [ ] 检查所有反序列化入口点（JSON/YAML/Protobuf）",
        "- [ ] 审查文件操作的路径规范化逻辑",
        "- [ ] 确认所有随机数生成使用 `crypto/rand`",
        "",
    ]

    # 依赖升级清单
    fixable = [v for v in advisories if _get_fix_version(v) and v.get("severity") in ("CRITICAL", "HIGH")]
    if fixable:
        lines += [
            "### 依赖升级清单（CRITICAL/HIGH 有修复版本）",
            "",
            "| 包名 | 当前受影响版本 | 修复版本 | CVE/GHSA |",
            "|------|--------------|---------|---------|",
        ]
        seen_pkgs = set()
        for v in fixable[:20]:
            pkg = _get_package_name(v)
            if pkg in seen_pkgs:
                continue
            seen_pkgs.add(pkg)
            fix = _get_fix_version(v)
            vid = v.get("cve_id") or v.get("ghsa_id") or v.get("id") or "N/A"
            vuln_range = _get_vuln_range(v)
            lines.append(f"| `{pkg}` | {vuln_range} | **{fix}** | `{vid}` |")
        lines.append("")

    lines.append("---")
    lines.append("")

    # 附录
    lines += [
        "## 附录",
        "",
        "### 数据来源说明",
        "",
        "| 来源 | URL | 说明 |",
        "|------|-----|------|",
        "| Go 官方漏洞库 | https://vuln.go.dev | Go 团队维护的权威漏洞数据库 |",
        "| OSV.dev | https://osv.dev | 开源漏洞数据库，覆盖 Go 生态 |",
        "| GitHub Advisory | https://github.com/advisories | GitHub 安全公告数据库 |",
        "| NVD | https://nvd.nist.gov | NIST 国家漏洞数据库 |",
        "",
        "### 漏洞类型编码说明",
        "",
        "| 编码 | 含义 |",
        "|------|------|",
    ]
    for code, desc in VULN_CATEGORIES.items():
        lines.append(f"| `{code}` | {desc} |")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML 日报
# ---------------------------------------------------------------------------

def generate_html(data: dict, date_str: str) -> str:
    advisories = data.get("advisories", [])
    sev_counts = data.get("severity_counts", {})
    cat_counts = data.get("category_counts", {})
    total = data.get("total", len(advisories))

    def h(text: str) -> str:
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    def sev_badge(sev: str) -> str:
        c = SEVERITY_COLORS.get(sev, "#546e7a")
        return f'<span class="badge" style="background:{c}">{h(sev)}</span>'

    def cat_badge(cat: str) -> str:
        c = CATEGORY_COLORS.get(cat, "#546e7a")
        label = VULN_CATEGORIES.get(cat, cat)
        return f'<span class="badge badge-cat" style="background:{c}">{h(label)}</span>'

    critical_high = [v for v in advisories if v.get("severity") in ("CRITICAL", "HIGH")]
    dominant_cats = [cat for cat, _ in sorted(cat_counts.items(), key=lambda x: -x[1])[:5]] if cat_counts else []

    overall_risk = "CRITICAL" if sev_counts.get("CRITICAL", 0) > 0 else \
                   "HIGH" if sev_counts.get("HIGH", 0) > 0 else \
                   "MEDIUM" if sev_counts.get("MEDIUM", 0) > 0 else "LOW"
    risk_color = SEVERITY_COLORS.get(overall_risk, "#546e7a")

    # 构建漏洞详情行
    vuln_rows = ""
    for v in advisories[:200]:
        vid = h(v.get("id") or v.get("cve_id") or v.get("ghsa_id") or "N/A")
        pkg = h(_get_package_name(v))
        sev = v.get("severity", "UNKNOWN")
        cat = v.get("category", "G-OTHER")
        title = h((v.get("title") or "")[:80])
        fix = h(_get_fix_version(v) or "—")
        cvss = v.get("cvss_score") or "—"
        desc = h((v.get("description") or "")[:300])
        ref_url = next((r for r in v.get("references", []) if r), "#")

        vuln_rows += f"""
        <tr class="sev-{sev.lower()}">
          <td><a href="{h(ref_url)}" target="_blank"><code>{vid}</code></a></td>
          <td><code>{pkg}</code></td>
          <td>{sev_badge(sev)}</td>
          <td>{cat_badge(cat)}</td>
          <td>{h(fix)}</td>
          <td class="num">{cvss}</td>
          <td class="desc">{title}</td>
        </tr>
        <tr class="desc-row">
          <td colspan="7" class="desc-cell">{desc}</td>
        </tr>"""

    # 防御建议卡片
    defense_cards = ""
    for cat in dominant_cats:
        label = VULN_CATEGORIES.get(cat, cat)
        color = CATEGORY_COLORS.get(cat, "#546e7a")
        defense = DEFENSE_TEMPLATES.get(cat, DEFENSE_TEMPLATES["G-OTHER"]).strip()
        defense_html = "<br>".join(
            f"<li>{h(line[2:].strip())}</li>" if line.startswith("- ") else h(line)
            for line in defense.split("\n") if line.strip()
        )
        defense_cards += f"""
        <div class="defense-card">
          <div class="defense-header" style="background:{color}">
            <strong>{h(cat)}</strong> — {h(label)}
          </div>
          <ul class="defense-list">{defense_html}</ul>
        </div>"""

    # 分类统计图（纯 CSS 进度条）
    cat_bars = ""
    max_cat = max(cat_counts.values()) if cat_counts else 1
    for cat, count in sorted(cat_counts.items(), key=lambda x: -x[1])[:8]:
        label = VULN_CATEGORIES.get(cat, cat)
        pct = count / max_cat * 100
        color = CATEGORY_COLORS.get(cat, "#546e7a")
        cat_bars += f"""
        <div class="bar-row">
          <div class="bar-label">{h(cat)}</div>
          <div class="bar-track">
            <div class="bar-fill" style="width:{pct:.0f}%;background:{color}"></div>
          </div>
          <div class="bar-count">{count}</div>
          <div class="bar-desc">{h(label)}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Go 安全日报 — {h(date_str)}</title>
  <style>
    :root {{
      --font: -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Microsoft YaHei', sans-serif;
      --bg: #f5f5f5;
      --card: #ffffff;
      --border: #e0e0e0;
      --text: #212121;
      --muted: #757575;
      --code-bg: #f1f1f1;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.7; font-size: 14px; }}
    header {{ background: #1a1a2e; color: white; padding: 1.5rem 2rem; border-bottom: 4px solid {risk_color}; }}
    header h1 {{ font-size: 1.5rem; margin-bottom: 0.3rem; }}
    header .meta {{ color: #b0bec5; font-size: 0.82rem; }}
    nav {{ background: #16213e; padding: 0.4rem 2rem; display: flex; gap: 1.5rem; flex-wrap: wrap; }}
    nav a {{ color: #90caf9; text-decoration: none; font-size: 0.85rem; padding: 0.3rem 0; }}
    nav a:hover {{ color: white; }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 1.5rem; }}
    section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1.5rem; }}
    h2 {{ font-size: 1.15rem; margin-bottom: 0.8rem; padding-bottom: 0.4rem; border-bottom: 2px solid var(--border); }}
    h3 {{ font-size: 1rem; margin: 0.8rem 0 0.5rem; color: #37474f; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px, 1fr)); gap: 0.8rem; }}
    .stat-card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem; text-align: center; }}
    .stat-card .value {{ font-size: 1.8rem; font-weight: 700; }}
    .stat-card .label {{ font-size: 0.72rem; color: var(--muted); text-transform: uppercase; }}
    .risk-pill {{ display: inline-block; background: {risk_color}; color: white; padding: 0.3rem 1rem; border-radius: 4px; font-weight: 700; }}
    .badge {{ display: inline-block; color: white; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.72rem; font-weight: 600; white-space: nowrap; }}
    .badge-cat {{ font-size: 0.68rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.85rem; }}
    th {{ background: #eceff1; text-align: left; padding: 0.5rem 0.7rem; border: 1px solid var(--border); font-weight: 600; white-space: nowrap; }}
    td {{ padding: 0.4rem 0.7rem; border: 1px solid var(--border); vertical-align: middle; }}
    tr.desc-row {{ display: none; }}
    tr.desc-row.open {{ display: table-row; }}
    tr.desc-row td {{ background: #f9fbe7; color: #555; font-size: 0.82rem; padding: 0.5rem 1rem; border-top: none; }}
    tr.sev-critical td {{ border-left: 3px solid {SEVERITY_COLORS["CRITICAL"]}; }}
    tr.sev-high td {{ border-left: 3px solid {SEVERITY_COLORS["HIGH"]}; }}
    tr.sev-medium td {{ border-left: 3px solid {SEVERITY_COLORS["MEDIUM"]}; }}
    tr.sev-low td {{ border-left: 3px solid {SEVERITY_COLORS["LOW"]}; }}
    td.desc {{ max-width: 280px; color: var(--muted); }}
    td.num {{ text-align: center; }}
    code {{ background: var(--code-bg); padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.82rem; }}
    a {{ color: #1565c0; }}
    .bar-row {{ display: flex; align-items: center; gap: 0.5rem; margin-bottom: 0.4rem; }}
    .bar-label {{ width: 90px; font-size: 0.78rem; font-weight: 600; color: #37474f; }}
    .bar-track {{ flex: 1; background: #eceff1; border-radius: 4px; height: 16px; overflow: hidden; }}
    .bar-fill {{ height: 100%; border-radius: 4px; }}
    .bar-count {{ width: 30px; text-align: right; font-size: 0.78rem; font-weight: 700; }}
    .bar-desc {{ font-size: 0.75rem; color: var(--muted); min-width: 120px; }}
    .defense-cards {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; }}
    .defense-card {{ border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }}
    .defense-header {{ color: white; padding: 0.5rem 0.8rem; font-size: 0.85rem; }}
    .defense-list {{ padding: 0.7rem 1rem; list-style: disc; font-size: 0.82rem; line-height: 1.8; }}
    .checklist {{ list-style: none; padding: 0; }}
    .checklist li {{ padding: 0.3rem 0; font-size: 0.85rem; border-bottom: 1px solid var(--border); }}
    .checklist li::before {{ content: "☐ "; color: #90a4ae; }}
    .toggle-btn {{ cursor: pointer; font-size: 0.75rem; color: #1565c0; }}
    footer {{ text-align: center; color: var(--muted); font-size: 0.78rem; padding: 1.5rem; }}
    @media (max-width: 768px) {{ main {{ padding: 0.8rem; }} table {{ font-size: 0.78rem; }} }}
  </style>
</head>
<body>
<header>
  <h1>🔐 Go 开源项目安全日报</h1>
  <div class="meta">
    日期: <strong>{h(date_str)}</strong> &nbsp;|&nbsp;
    生成时间: <strong>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</strong> &nbsp;|&nbsp;
    数据来源: Go 官方漏洞库 / OSV.dev / GitHub Advisory / NVD
  </div>
</header>
<nav>
  <a href="#summary">执行摘要</a>
  <a href="#critical-high">高危漏洞</a>
  <a href="#all-vulns">全部漏洞</a>
  <a href="#patterns">漏洞特征</a>
  <a href="#defense">防御建议</a>
  <a href="#upgrade">升级清单</a>
</nav>
<main>

  <section id="summary">
    <h2>执行摘要</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="value"><span class="risk-pill">{h(overall_risk)}</span></div>
        <div class="label">整体风险等级</div>
      </div>
      <div class="stat-card">
        <div class="value">{total}</div>
        <div class="label">新增漏洞总数</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['CRITICAL']}">{sev_counts.get('CRITICAL', 0)}</div>
        <div class="label">🔴 CRITICAL</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['HIGH']}">{sev_counts.get('HIGH', 0)}</div>
        <div class="label">🟠 HIGH</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['MEDIUM']}">{sev_counts.get('MEDIUM', 0)}</div>
        <div class="label">🟡 MEDIUM</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['LOW']}">{sev_counts.get('LOW', 0)}</div>
        <div class="label">🟢 LOW</div>
      </div>
    </div>
  </section>

  <section id="patterns">
    <h2>漏洞特征分析</h2>
    <h3>本期漏洞类型分布</h3>
    <div style="margin-top:0.5rem">{cat_bars or '<p style="color:var(--muted)">暂无分类数据</p>'}</div>
  </section>

  <section id="all-vulns">
    <h2>漏洞列表（{total} 条，点击行展开描述）</h2>
    {"<p style='color:var(--muted)'>今日暂无新增漏洞</p>" if not advisories else f"""
    <table>
      <thead>
        <tr>
          <th>编号</th><th>受影响包</th><th>严重度</th><th>漏洞类型</th>
          <th>修复版本</th><th>CVSS</th><th>摘要</th>
        </tr>
      </thead>
      <tbody id="vuln-tbody">{vuln_rows}</tbody>
    </table>"""}
  </section>

  <section id="defense">
    <h2>防御建议</h2>
    <h3>本期高频漏洞类型加固方案</h3>
    <div class="defense-cards" style="margin-top:0.8rem">{defense_cards or "<p style='color:var(--muted)'>暂无数据</p>"}</div>

    <h3 style="margin-top:1.2rem">通用 Go 安全加固 Checklist</h3>
    <ul class="checklist">
      <li>运行 <code>govulncheck ./...</code> 检查已知漏洞依赖</li>
      <li>CI 流水线启用 <code>go test -race ./...</code></li>
      <li>审计所有 <code>unsafe</code> 包使用位置</li>
      <li>所有 HTTP handler 设置超时和请求体大小限制</li>
      <li>验证 TLS 配置（<code>MinVersion: tls.VersionTLS12</code>）</li>
      <li>检查反序列化入口点（JSON/YAML/Protobuf）大小限制</li>
      <li>审查文件操作中路径规范化逻辑</li>
      <li>确认随机数生成使用 <code>crypto/rand</code></li>
      <li>审计第三方包依赖，启用 <code>go.sum</code> 验证</li>
    </ul>
  </section>

  <section id="upgrade">
    <h2>依赖升级清单</h2>
    <p style="color:var(--muted);font-size:0.85rem;margin-bottom:0.8rem">以下 CRITICAL/HIGH 漏洞已有修复版本，建议优先升级：</p>
    {_build_upgrade_table(advisories, h)}
  </section>

</main>
<footer>
  Go 开源项目安全日报 &nbsp;|&nbsp; 数据来源: vuln.go.dev / osv.dev / github.com/advisories / nvd.nist.gov
  &nbsp;|&nbsp; {h(date_str)}
</footer>
<script>
  // 点击行展开/收起描述
  document.querySelectorAll('#vuln-tbody tr:not(.desc-row)').forEach(row => {{
    row.style.cursor = 'pointer';
    row.addEventListener('click', () => {{
      const next = row.nextElementSibling;
      if (next && next.classList.contains('desc-row')) {{
        next.classList.toggle('open');
      }}
    }});
  }});
</script>
</body>
</html>"""
    return html


def _build_upgrade_table(advisories: list[dict], h) -> str:
    fixable = [v for v in advisories if _get_fix_version(v) and v.get("severity") in ("CRITICAL", "HIGH")]
    if not fixable:
        return "<p style='color:var(--muted)'>暂无需要升级的 CRITICAL/HIGH 漏洞。</p>"

    rows = ""
    seen = set()
    for v in fixable[:30]:
        pkg = _get_package_name(v)
        if pkg in seen:
            continue
        seen.add(pkg)
        fix = _get_fix_version(v)
        vid = v.get("cve_id") or v.get("ghsa_id") or v.get("id") or "N/A"
        sev = v.get("severity", "UNKNOWN")
        vuln_range = _get_vuln_range(v)
        color = SEVERITY_COLORS.get(sev, "#546e7a")
        rows += f"""
        <tr>
          <td><code>{h(pkg)}</code></td>
          <td><code>{h(vuln_range)}</code></td>
          <td><strong>{h(fix)}</strong></td>
          <td><span class="badge" style="background:{color}">{h(sev)}</span></td>
          <td><code>{h(vid)}</code></td>
        </tr>"""

    return f"""<table>
      <thead><tr><th>包名</th><th>受影响版本</th><th>修复版本</th><th>严重度</th><th>编号</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>"""


# ---------------------------------------------------------------------------
# 辅助函数
# ---------------------------------------------------------------------------

def _get_package_name(v: dict) -> str:
    affected = v.get("affected", [])
    if affected:
        first = affected[0]
        pkg = first.get("package") or ""
        if pkg:
            return pkg
    # GitHub advisory format
    raw = v.get("_raw", {})
    for vp in raw.get("vulnerabilities", []):
        pkg = vp.get("package", {}).get("name", "")
        if pkg:
            return pkg
    return v.get("id", "unknown")[:40]


def _get_fix_version(v: dict) -> str:
    affected = v.get("affected", [])
    for a in affected:
        fix_versions = a.get("fixed_versions", [])
        for fv in fix_versions:
            if isinstance(fv, dict) and fv.get("fixed"):
                return fv["fixed"]
        fixed_at = a.get("fixed_at")
        if fixed_at:
            return str(fixed_at)
    return ""


def _get_vuln_range(v: dict) -> str:
    affected = v.get("affected", [])
    for a in affected:
        r = a.get("vulnerable_version_range", "")
        if r:
            return r
        for fv in a.get("fixed_versions", []):
            if isinstance(fv, dict) and fv.get("fixed"):
                return f"< {fv['fixed']}"
    return "见详情"


def _get_pattern_summary(cat: str) -> str:
    summaries = {
        "G-DOS": "拒绝服务漏洞是本期 Go 项目中最常见的漏洞类型。主要原因包括：HTTP/2 流处理无限制、正则表达式回溯、内存分配无上限和 goroutine 泄漏。攻击者无需认证即可触发，影响服务可用性。",
        "G-AUTH": "认证授权绕过漏洞通常由 JWT 算法混淆、RBAC 策略逻辑错误或中间件顺序问题引起。在 Kubernetes 等多租户系统中危害尤为严重。",
        "G-INJ": "注入类漏洞在 Go 中主要体现在模板注入（text/template vs html/template）和命令执行（exec.Command with shell）场景。",
        "G-PROTO": "序列化漏洞常见于 YAML 解析器（gopkg.in/yaml.v2 任意代码执行）、Protobuf 消息体积无限制和 JSON 解析器资源耗尽。",
        "G-PATH": "路径遍历漏洞在容器运行时（如 runc, containerd）和文件服务器场景中高发，通常由 filepath.Join 未正确处理 '..' 序列引起。",
        "G-CRYPTO": "密码学问题包括使用弱随机数（math/rand）、TLS 配置宽松（InsecureSkipVerify）和证书链验证绕过。",
        "G-SSRF": "SSRF 漏洞在使用 http.Client 处理用户提供的 URL 时高发，容器和 Kubernetes 环境中可被用于访问云元数据服务。",
        "G-RACE": "竞争条件漏洞通常在高并发场景下难以复现，Go 的 -race 标志可有效检测，但需要在测试中模拟并发场景。",
    }
    return summaries.get(cat, f"{VULN_CATEGORIES.get(cat, cat)} 类漏洞，请参考 references/go_vuln_patterns.md 获取详细分析。")


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="生成 Go 安全日报")
    parser.add_argument("--raw-file", required=True, help="fetch_advisories.py 输出的 JSON 文件路径")
    parser.add_argument("--output-dir", default="./go-security-reports", help="输出目录")
    parser.add_argument(
        "--format",
        choices=["html", "markdown", "both"],
        default="both",
        help="输出格式（默认 both）",
    )
    parser.add_argument("--date", help="报告日期（YYYY-MM-DD），默认从文件中读取")
    args = parser.parse_args()

    raw_file = Path(args.raw_file)
    if not raw_file.exists():
        print(f"ERROR: 找不到文件 {raw_file}", file=sys.stderr)
        sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"加载数据: {raw_file}")
    data = load_raw(str(raw_file))

    # 从文件路径或参数推断日期
    date_str = args.date or data.get("date") or raw_file.parent.name or \
               datetime.now(timezone.utc).strftime("%Y-%m-%d")

    total = data.get("total", len(data.get("advisories", [])))
    sev = data.get("severity_counts", {})
    print(f"漏洞总数: {total}  CRITICAL={sev.get('CRITICAL',0)} HIGH={sev.get('HIGH',0)} "
          f"MEDIUM={sev.get('MEDIUM',0)} LOW={sev.get('LOW',0)}")

    reports = []

    if args.format in ("html", "both"):
        out_path = output_dir / f"go-security-digest-{date_str}.html"
        print(f"生成 HTML 日报...")
        html = generate_html(data, date_str)
        out_path.write_text(html, encoding="utf-8")
        reports.append(str(out_path))
        print(f"  HTML: {out_path}")

    if args.format in ("markdown", "both"):
        out_path = output_dir / f"go-security-digest-{date_str}.md"
        print(f"生成 Markdown 日报...")
        md = generate_markdown(data, date_str)
        out_path.write_text(md, encoding="utf-8")
        reports.append(str(out_path))
        print(f"  Markdown: {out_path}")

    overall_risk = "CRITICAL" if sev.get("CRITICAL", 0) > 0 else \
                   "HIGH" if sev.get("HIGH", 0) > 0 else \
                   "MEDIUM" if sev.get("MEDIUM", 0) > 0 else "LOW"

    print(f"\n{'='*60}")
    print(f"Go 安全日报生成完成")
    print(f"{'='*60}")
    print(f"日期       : {date_str}")
    print(f"整体风险   : {overall_risk}")
    print(f"漏洞总数   : {total}")
    print(f"报告文件   :")
    for r in reports:
        print(f"  {r}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
