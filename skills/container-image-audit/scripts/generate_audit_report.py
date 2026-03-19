#!/usr/bin/env python3
"""
容器镜像安全审计报告生成器（渗透测试风格）

生成包含攻击链分析的 HTML 报告，包括：
  - 执行摘要与风险矩阵
  - 攻击场景建模（Top 5 攻击链）
  - P0/P1 高危发现详情
  - 危险资产清单（攻击者武器库）
  - CVE 漏洞详情（按可利用性排序）
  - 修复优先级矩阵

用法:
    python3 scripts/generate_audit_report.py \\
        --audit-json ./audit-report/audit_results.json \\
        --output-dir ./audit-report \\
        --format html
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


RISK_COLORS = {
    "CRITICAL": "#b71c1c", "HIGH": "#e65100",
    "MEDIUM":   "#f57f17", "LOW":  "#388e3c",
    "PASS":     "#2e7d32", "UNKNOWN": "#546e7a",
}
PRIORITY_COLORS = {
    "P0": "#b71c1c", "P1": "#e65100",
    "P2": "#f57f17", "P3": "#388e3c",
}
LIKELIHOOD_COLORS = {
    "CONFIRMED": "#b71c1c", "HIGH": "#e65100",
    "MEDIUM":    "#f57f17", "LOW":  "#388e3c",
}


def _h(t: str) -> str:
    return str(t).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")


def _badge(text: str, color: str, small: bool = False) -> str:
    fs = "0.72rem" if small else "0.8rem"
    return (f'<span style="background:{color};color:white;padding:0.2rem 0.6rem;'
            f'border-radius:3px;font-size:{fs};font-weight:600;white-space:nowrap">'
            f'{_h(str(text))}</span>')


def _risk_badge(risk: str) -> str:
    return _badge(risk, RISK_COLORS.get(risk, "#546e7a"))


def _sev_icon(sev: str) -> str:
    icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","UNKNOWN":"⚪","CONFIRMED":"🔴"}
    return icons.get(sev, "⚪")


def load_audit(audit_json: str) -> dict:
    with open(audit_json, encoding="utf-8") as f:
        return json.load(f)


def generate_html(data: dict, date_str: str) -> str:
    phase1 = data.get("phase1", {})
    phase2 = data.get("phase2", {})
    phase3 = data.get("phase3", {})
    target = data.get("target", "unknown")
    overall_risk = data.get("overall_risk", "UNKNOWN")
    exec_summary = data.get("executive_summary", "")
    risk_color = RISK_COLORS.get(overall_risk, "#546e7a")

    # ── 统计 ─────────────────────────────────────────────────
    crit_vulns  = phase1.get("critical_vulns", [])
    high_vulns  = phase1.get("high_vulns", [])
    all_vulns   = phase2.get("all_vulns", [])
    misconfigs  = phase2.get("misconfigs", [])
    secrets     = phase1.get("secrets", [])
    bin_audit   = phase2.get("bin_audit", {})
    attack_chains   = phase3.get("attack_chains", [])
    escape_vectors  = phase3.get("escape_vectors", [])
    priority_matrix = phase3.get("priority_matrix", [])
    vuln_counts = phase2.get("vuln_counts", {}) or phase1.get("quick_vuln_counts", {})
    sbom_summary = phase2.get("sbom_summary", {})

    p0_items = [x for x in priority_matrix if x.get("priority") == "P0"]
    p1_items = [x for x in priority_matrix if x.get("priority") == "P1"]
    runs_as_root = phase1.get("runs_as_root", False)

    # ── 攻击链卡片 ──────────────────────────────────────────
    chain_cards = ""
    for chain in attack_chains:
        lhood = chain.get("likelihood", "MEDIUM")
        color = LIKELIHOOD_COLORS.get(lhood, "#f57f17")
        steps_html = "".join(f"<li>{_h(s)}</li>" for s in chain.get("steps", []))
        related = ""
        if chain.get("cves"):
            related = f'<div class="chain-related">CVE: {", ".join(_h(c) for c in chain["cves"][:3])}</div>'
        if chain.get("secrets"):
            related += f'<div class="chain-related">密钥: {", ".join(_h(s) for s in chain["secrets"][:2])}</div>'
        chain_cards += f"""
        <div class="chain-card">
          <div class="chain-header" style="border-left:4px solid {color}">
            <span class="chain-id">{_h(chain.get("id",""))}</span>
            <span class="chain-name">{_h(chain.get("name",""))}</span>
            <span>{_badge(lhood, color, True)} {_badge(chain.get("impact","?"), RISK_COLORS.get(chain.get("impact","?"), "#546e7a"), True)}</span>
          </div>
          <ol class="chain-steps">{steps_html}</ol>
          {related}
        </div>"""

    # ── 危险二进制卡片 ────────────────────────────────────────
    bin_cards = ""
    for risk_level in ("CRITICAL", "HIGH", "MEDIUM"):
        bins = bin_audit.get("found", {}).get(risk_level, [])
        if not bins:
            continue
        color = RISK_COLORS.get(risk_level, "#546e7a")
        for b in bins:
            bin_cards += f"""
            <div class="bin-card">
              <div class="bin-name" style="color:{color}">{_h(b['binary'])}</div>
              <div class="bin-pkg">包: {_h(b.get('package','?'))}</div>
              <div class="bin-use">🔧 {_h(b.get('attack_use',''))}</div>
              <div>{_badge(risk_level, color, True)}</div>
            </div>"""

    # ── CVE 表格 ──────────────────────────────────────────────
    vuln_rows = ""
    display_vulns = all_vulns if all_vulns else (crit_vulns + high_vulns)
    for v in display_vulns[:150]:
        sev = v.get("severity", "UNKNOWN")
        color = RISK_COLORS.get(sev, "#546e7a")
        fix_cell = (f'<span style="color:#2e7d32;font-weight:600">{_h(v.get("fix",""))}</span>'
                    if v.get("fix") else '<span style="color:#b0bec5">—</span>')
        exploit_badge = ('<span style="background:#b71c1c;color:white;padding:0.1rem 0.4rem;'
                         'border-radius:3px;font-size:0.7rem">PoC</span>'
                         if v.get("known_exploit") else "")
        url = _h(v.get("primary_url") or "#")
        vuln_rows += f"""
        <tr>
          <td><a href="{url}" target="_blank"><code style="font-size:0.8rem">{_h(v.get("vuln_id",""))}</code></a>{exploit_badge}</td>
          <td><code style="font-size:0.78rem">{_h(v.get("pkg",""))}</code></td>
          <td style="font-size:0.78rem">{_h(v.get("version",""))}</td>
          <td>{fix_cell}</td>
          <td>{_badge(sev, color, True)}</td>
          <td style="text-align:center;font-size:0.8rem">{v.get("cvss") or "—"}</td>
          <td style="max-width:260px;font-size:0.78rem;color:#546e7a">{_h((v.get("title") or "")[:80])}</td>
        </tr>"""

    # ── 优先级矩阵 ────────────────────────────────────────────
    priority_rows = ""
    for item in priority_matrix:
        p = item.get("priority", "P3")
        color = PRIORITY_COLORS.get(p, "#546e7a")
        type_icon = {"CVE":"🔓","SECRET":"🔑","MISCONFIG":"⚙️","BINARY":"🔧"}.get(item.get("type",""), "📋")
        priority_rows += f"""
        <tr>
          <td>{_badge(p, color)}</td>
          <td>{type_icon} {_h(item.get("type",""))}</td>
          <td><code style="font-size:0.8rem">{_h(item.get("id",""))}</code></td>
          <td style="font-size:0.82rem">{_h(item.get("title",""))}</td>
          <td style="font-size:0.82rem;color:#1b5e20">{_h(item.get("action",""))}</td>
        </tr>"""

    # ── 配置问题 ──────────────────────────────────────────────
    misconfig_rows = ""
    for m in misconfigs[:30]:
        sev = m.get("severity", "UNKNOWN")
        misconfig_rows += f"""
        <tr>
          <td><code style="font-size:0.8rem">{_h(m.get("id",""))}</code></td>
          <td style="font-size:0.82rem">{_h(m.get("title",""))}</td>
          <td>{_badge(sev, RISK_COLORS.get(sev,"#546e7a"), True)}</td>
          <td style="font-size:0.78rem;color:#546e7a">{_h(m.get("resolution","")[:100])}</td>
        </tr>"""

    # ── 逃逸向量 ──────────────────────────────────────────────
    escape_rows = ""
    for ev in escape_vectors:
        sev = ev.get("severity", "HIGH")
        escape_rows += f"""
        <div class="escape-item" style="border-left:3px solid {RISK_COLORS.get(sev,'#e65100')}">
          <div class="escape-header">{_badge(sev, RISK_COLORS.get(sev,'#e65100'), True)} {_h(ev.get("desc",""))}</div>
          <div class="escape-detail">{_h(ev.get("detail",""))}</div>
          {f'<div class="escape-cis">CIS 参考: {_h(ev.get("cis_ref",""))}</div>' if ev.get("cis_ref") else ""}
        </div>"""

    css = f"""
    :root {{
      --font: -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Segoe UI', sans-serif;
      --bg: #0d1117; --card: #161b22; --border: #30363d;
      --text: #e6edf3; --muted: #8b949e; --code-bg: #21262d;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: var(--font); background: var(--bg); color: var(--text);
            line-height: 1.7; font-size: 14px; }}
    header {{ background: #0d1117; border-bottom: 3px solid {risk_color};
              padding: 1.5rem 2rem; }}
    header h1 {{ font-size: 1.4rem; color: {risk_color}; }}
    header .meta {{ color: var(--muted); font-size: 0.8rem; margin-top: 0.3rem; }}
    nav {{ background: #161b22; border-bottom: 1px solid var(--border);
           padding: 0.4rem 2rem; display: flex; gap: 1.5rem; flex-wrap: wrap; }}
    nav a {{ color: #58a6ff; text-decoration: none; font-size: 0.82rem; }}
    nav a:hover {{ color: #79c0ff; }}
    main {{ max-width: 1300px; margin: 0 auto; padding: 1.5rem; }}
    section {{ background: var(--card); border: 1px solid var(--border);
               border-radius: 6px; padding: 1.2rem 1.5rem; margin-bottom: 1.5rem; }}
    h2 {{ font-size: 1.05rem; border-bottom: 1px solid var(--border);
          padding-bottom: 0.5rem; margin-bottom: 1rem; color: #c9d1d9; }}
    h3 {{ font-size: 0.95rem; color: #8b949e; margin: 0.8rem 0 0.4rem; }}
    /* Stats grid */
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(130px,1fr)); gap: 0.8rem; }}
    .stat-card {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px;
                  padding: 0.8rem; text-align: center; }}
    .stat-val {{ font-size: 2rem; font-weight: 700; }}
    .stat-lbl {{ font-size: 0.7rem; color: var(--muted); text-transform: uppercase; margin-top: 0.1rem; }}
    .risk-pill {{ display: inline-block; background: {risk_color}; color: white;
                  padding: 0.3rem 1rem; border-radius: 4px; font-weight: 700; font-size: 1.1rem; }}
    /* Attack chains */
    .chains-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(340px,1fr)); gap: 1rem; }}
    .chain-card {{ background: #0d1117; border: 1px solid var(--border); border-radius: 6px;
                   padding: 0.8rem; }}
    .chain-header {{ display: flex; align-items: center; gap: 0.6rem; flex-wrap: wrap;
                     margin-bottom: 0.6rem; padding-left: 0.5rem; }}
    .chain-id {{ font-size: 0.72rem; color: var(--muted); font-family: monospace; }}
    .chain-name {{ font-weight: 600; font-size: 0.9rem; flex: 1; }}
    .chain-steps {{ padding-left: 1.2rem; font-size: 0.82rem; color: #c9d1d9; line-height: 1.9; }}
    .chain-related {{ font-size: 0.75rem; color: var(--muted); margin-top: 0.4rem; }}
    /* Binary inventory */
    .bin-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(200px,1fr)); gap: 0.7rem; }}
    .bin-card {{ background: #0d1117; border: 1px solid var(--border); border-radius: 5px;
                 padding: 0.7rem; }}
    .bin-name {{ font-size: 1rem; font-weight: 700; font-family: monospace; margin-bottom: 0.2rem; }}
    .bin-pkg  {{ font-size: 0.72rem; color: var(--muted); }}
    .bin-use  {{ font-size: 0.75rem; color: #c9d1d9; margin: 0.3rem 0; line-height: 1.4; }}
    /* Tables */
    table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-top: 0.5rem; }}
    th {{ background: #21262d; text-align: left; padding: 0.5rem 0.7rem;
          border: 1px solid var(--border); font-weight: 600; color: var(--muted);
          white-space: nowrap; }}
    td {{ padding: 0.4rem 0.7rem; border: 1px solid var(--border); vertical-align: middle; }}
    tr:hover {{ background: #1c2128; }}
    code {{ background: var(--code-bg); padding: 0.1rem 0.35rem; border-radius: 3px;
            color: #e6edf3; }}
    a {{ color: #58a6ff; }}
    /* Escape vectors */
    .escape-item {{ background: #0d1117; border: 1px solid var(--border); border-radius: 5px;
                    padding: 0.7rem 0.9rem; margin-bottom: 0.5rem; }}
    .escape-header {{ font-weight: 600; font-size: 0.88rem; display: flex; align-items:center; gap:0.5rem; }}
    .escape-detail {{ font-size: 0.8rem; color: var(--muted); margin-top: 0.3rem; }}
    .escape-cis {{ font-size: 0.72rem; color: #8b949e; margin-top: 0.2rem; }}
    /* Alert */
    .alert-critical {{ background: #2d0000; border: 1px solid #b71c1c;
                       border-left: 4px solid #b71c1c; padding: 0.8rem 1rem;
                       border-radius: 4px; margin-bottom: 1rem; font-size: 0.85rem; }}
    .exec-summary {{ font-size: 0.85rem; color: #c9d1d9; margin-top: 0.7rem;
                     background: #0d1117; padding: 0.8rem; border-radius: 5px; }}
    footer {{ text-align:center; color:var(--muted); font-size:0.75rem; padding: 1.5rem; }}
    """

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>容器镜像安全审计 — {_h(target)}</title>
  <style>{css}</style>
</head>
<body>
<header>
  <h1>🔐 容器镜像安全审计报告（渗透测试视角）</h1>
  <div class="meta">
    目标: <strong>{_h(target)}</strong> &nbsp;|&nbsp;
    审计时间: <strong>{_h(date_str)}</strong> &nbsp;|&nbsp;
    整体风险: <strong style="color:{risk_color}">{_h(overall_risk)}</strong>
  </div>
</header>
<nav>
  <a href="#summary">执行摘要</a>
  <a href="#attack-chains">攻击链</a>
  <a href="#priority">优先级矩阵</a>
  <a href="#escape">逃逸向量</a>
  <a href="#arsenal">武器库</a>
  <a href="#vulns">CVE 详情</a>
  <a href="#misconfig">配置检查</a>
</nav>
<main>

  <!-- 执行摘要 -->
  <section id="summary">
    <h2>执行摘要</h2>
    {"<div class='alert-critical'>⚠️ <strong>CRITICAL — 需立即行动：</strong> " + _h(exec_summary) + "</div>" if overall_risk == "CRITICAL" else ""}
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-val"><span class="risk-pill">{_h(overall_risk)}</span></div>
        <div class="stat-lbl">整体风险</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color:{RISK_COLORS['CRITICAL']}">{len(p0_items)}</div>
        <div class="stat-lbl">P0 立即行动</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color:{RISK_COLORS['HIGH']}">{len(p1_items)}</div>
        <div class="stat-lbl">P1 7天内修复</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color:{RISK_COLORS['CRITICAL']}">{len(secrets)}</div>
        <div class="stat-lbl">密钥泄露</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color:{RISK_COLORS.get('HIGH' if runs_as_root else 'LOW','')}">{('是 ⚠' if runs_as_root else '否 ✓')}</div>
        <div class="stat-lbl">root 运行</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color:{RISK_COLORS['CRITICAL']}">{vuln_counts.get('CRITICAL',0)}</div>
        <div class="stat-lbl">CRITICAL CVE</div>
      </div>
      <div class="stat-card">
        <div class="stat-val" style="color:{RISK_COLORS['HIGH']}">{vuln_counts.get('HIGH',0) or len(high_vulns)}</div>
        <div class="stat-lbl">HIGH CVE</div>
      </div>
      <div class="stat-card">
        <div class="stat-val">{bin_audit.get("total_dangerous",0)}</div>
        <div class="stat-lbl">危险二进制</div>
      </div>
    </div>
    <div class="exec-summary">{_h(exec_summary)}</div>
  </section>

  <!-- 攻击链 -->
  <section id="attack-chains">
    <h2>🎯 攻击场景建模 — Top {len(attack_chains)} 攻击链</h2>
    <div class="chains-grid">{chain_cards or "<p style='color:var(--muted)'>暂无高置信度攻击链。</p>"}</div>
  </section>

  <!-- 优先级矩阵 -->
  <section id="priority">
    <h2>⚡ 修复优先级矩阵</h2>
    {"<p style='color:var(--muted)'>暂无高优先级发现。</p>" if not priority_matrix else f"""
    <table>
      <thead><tr>
        <th>优先级</th><th>类型</th><th>标识符</th><th>说明</th><th>修复行动</th>
      </tr></thead>
      <tbody>{priority_rows}</tbody>
    </table>"""}
  </section>

  <!-- 逃逸向量 -->
  <section id="escape">
    <h2>🚪 容器逃逸向量分析（静态评估）</h2>
    {escape_rows or "<p style='color:#388e3c'>✓ 未发现明显逃逸向量（建议结合运行时扫描确认）</p>"}
  </section>

  <!-- 武器库 -->
  <section id="arsenal">
    <h2>🔧 危险资产清单（攻击者武器库）</h2>
    <p style="color:var(--muted);font-size:0.82rem;margin-bottom:0.8rem">
      攻击者获得容器内代码执行后，以下工具可被用于后渗透操作。
      评级: <strong>{_h(bin_audit.get("attack_capability",""))}</strong>
    </p>
    <div class="bin-grid">{bin_cards or "<p style='color:#388e3c'>✓ 未发现高危工具（良好的最小化原则）</p>"}</div>
  </section>

  <!-- CVE 详情 -->
  <section id="vulns">
    <h2>🔓 CVE 漏洞详情（按可利用性排序）</h2>
    {"<p style='color:var(--muted)'>暂无 CVE 数据。</p>" if not display_vulns else f"""
    <p style="color:var(--muted);font-size:0.8rem;margin-bottom:0.5rem">
      共 {len(display_vulns)} 条（显示前 150 条）| 带 <span style='background:#b71c1c;color:white;padding:0.1rem 0.3rem;border-radius:2px;font-size:0.7rem'>PoC</span> 的为已知可利用漏洞
    </p>
    <table>
      <thead><tr>
        <th>CVE / ID</th><th>包名</th><th>当前版本</th><th>修复版本</th>
        <th>严重度</th><th>CVSS</th><th>描述</th>
      </tr></thead>
      <tbody>{vuln_rows}</tbody>
    </table>"""}
  </section>

  <!-- 配置检查 -->
  <section id="misconfig">
    <h2>⚙️ CIS 配置检查（失败项）</h2>
    {"<p style='color:#388e3c'>✓ 所有 CIS 配置项通过</p>" if not misconfigs else f"""
    <table>
      <thead><tr><th>控制 ID</th><th>标题</th><th>严重度</th><th>修复建议</th></tr></thead>
      <tbody>{misconfig_rows}</tbody>
    </table>"""}
  </section>

</main>
<footer>容器镜像安全审计报告 · 渗透测试视角 · {_h(date_str)}</footer>
</body>
</html>"""
    return html


def generate_markdown(data: dict, date_str: str) -> str:
    phase1 = data.get("phase1", {})
    phase2 = data.get("phase2", {})
    phase3 = data.get("phase3", {})
    target = data.get("target", "unknown")
    overall_risk = data.get("overall_risk", "UNKNOWN")
    exec_summary = data.get("executive_summary", "")
    attack_chains = phase3.get("attack_chains", [])
    priority_matrix = phase3.get("priority_matrix", [])
    escape_vectors = phase3.get("escape_vectors", [])
    all_vulns = phase2.get("all_vulns", [])
    crit_vulns = phase1.get("critical_vulns", [])
    high_vulns = phase1.get("high_vulns", [])
    secrets = phase1.get("secrets", [])
    bin_audit = phase2.get("bin_audit", {})
    vuln_counts = phase2.get("vuln_counts", {})

    risk_icons = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢"}
    ri = risk_icons.get(overall_risk, "⚪")

    lines = [
        f"# 容器镜像安全审计报告（渗透测试视角）",
        "",
        f"**目标**: `{target}`  ",
        f"**审计时间**: {date_str}  ",
        f"**整体风险**: {ri} **{overall_risk}**  ",
        "",
        "---",
        "",
        "## 执行摘要",
        "",
        f"> {exec_summary}",
        "",
        f"| 指标 | 数值 |",
        f"|------|------|",
        f"| 整体风险 | {ri} **{overall_risk}** |",
        f"| P0 立即行动 | {len([x for x in priority_matrix if x.get('priority')=='P0'])} |",
        f"| P1 7天内修复 | {len([x for x in priority_matrix if x.get('priority')=='P1'])} |",
        f"| 密钥泄露 | {'⚠️ ' + str(len(secrets)) if secrets else '✓ 无'} |",
        f"| root 运行 | {'⚠️ 是' if phase1.get('runs_as_root') else '✓ 否'} |",
        f"| CRITICAL CVE | {vuln_counts.get('CRITICAL', len(crit_vulns))} |",
        f"| HIGH CVE | {vuln_counts.get('HIGH', len(high_vulns))} |",
        f"| 危险二进制 | {bin_audit.get('total_dangerous', 0)} 个 |",
        "",
        "---",
        "",
        "## 🎯 攻击场景建模",
        "",
    ]

    for chain in attack_chains:
        lhood = chain.get("likelihood", "?")
        impact = chain.get("impact", "?")
        lines += [
            f"### {chain.get('id','')} — {chain.get('name','')}",
            "",
            f"**可能性**: {lhood} | **影响**: {impact}",
            "",
        ]
        for step in chain.get("steps", []):
            lines.append(f"{step}")
        if chain.get("cves"):
            lines += ["", f"*关联 CVE: {', '.join(chain['cves'][:3])}*"]
        lines.append("")

    lines += ["---", "", "## ⚡ 修复优先级矩阵", ""]
    if priority_matrix:
        lines += [
            "| 优先级 | 类型 | 标识符 | 说明 | 行动 |",
            "|--------|------|--------|------|------|",
        ]
        for item in priority_matrix[:15]:
            lines.append(
                f"| **{item.get('priority','')}** | {item.get('type','')} "
                f"| `{item.get('id','')}` | {item.get('title','')[:50]} "
                f"| {item.get('action','')[:60]} |"
            )
    lines += ["", "---", "", "## 🚪 容器逃逸向量", ""]
    for ev in escape_vectors:
        sev = ev.get("severity", "HIGH")
        lines += [
            f"- {risk_icons.get(sev,'⚪')} **[{sev}]** {ev.get('desc','')}  ",
            f"  {ev.get('detail','')}",
        ]
    if not escape_vectors:
        lines.append("✓ 未发现明显逃逸向量")

    lines += ["", "---", "", "## 🔧 危险资产清单", ""]
    cap = bin_audit.get("attack_capability", "")
    if cap:
        lines.append(f"> 攻击者后渗透能力评级: **{cap}**")
        lines.append("")
    for risk_level in ("CRITICAL", "HIGH"):
        bins = bin_audit.get("found", {}).get(risk_level, [])
        if bins:
            lines += [f"### {risk_icons.get(risk_level,'')} {risk_level}", ""]
            for b in bins:
                lines.append(f"- `{b['binary']}` — {b.get('attack_use','')}")
            lines.append("")

    lines += ["---", "", "## 🔓 高危 CVE（CRITICAL/HIGH）", ""]
    display_vulns = (crit_vulns + high_vulns) or [v for v in all_vulns if v.get("severity") in ("CRITICAL","HIGH")]
    if display_vulns:
        lines += [
            "| CVE | 包 | 当前版本 | 修复版本 | CVSS | PoC |",
            "|-----|---|---------|---------|------|-----|",
        ]
        for v in display_vulns[:20]:
            fix = v.get("fix") or "—"
            poc = "✅" if v.get("known_exploit") else "—"
            lines.append(
                f"| `{v.get('vuln_id','')}` | `{v.get('pkg','')}` "
                f"| {v.get('version','')} | {fix} "
                f"| {v.get('cvss') or '—'} | {poc} |"
            )
    lines += [""]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="生成容器镜像安全审计报告")
    parser.add_argument("--audit-json", required=True, help="audit_image.py 输出的 JSON 文件")
    parser.add_argument("--output-dir", default="./audit-report")
    parser.add_argument("--format", choices=["html","markdown","both"], default="html")
    parser.add_argument("--date", help="报告日期")
    args = parser.parse_args()

    out_dir   = Path(args.output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    data      = load_audit(args.audit_json)
    date_str  = args.date or data.get("audit_timestamp", "")[:10] \
                or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    target   = data.get("target", "unknown")
    risk     = data.get("overall_risk", "UNKNOWN")
    reports  = []

    if args.format in ("html", "both"):
        path = out_dir / "audit-report.html"
        path.write_text(generate_html(data, date_str), encoding="utf-8")
        reports.append(str(path))
        print(f"HTML 报告: {path}")

    if args.format in ("markdown", "both"):
        path = out_dir / "audit-report.md"
        path.write_text(generate_markdown(data, date_str), encoding="utf-8")
        reports.append(str(path))
        print(f"Markdown 报告: {path}")

    print(f"\n目标: {target} | 整体风险: {risk}")
    print(f"P0 行动项: {len([x for x in data.get('phase3',{}).get('priority_matrix',[]) if x.get('priority')=='P0'])}")


if __name__ == "__main__":
    main()
