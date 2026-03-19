#!/usr/bin/env python3
"""
Go 安全日报生成器 v2
按「漏洞模式」组织报告，每个模式展示：
  - 漏洞类型定义
  - 本期漏洞特征（从描述 + code diff 提取）
  - 代码修改前后对比（有 diff 时显示）
  - 防御方案
  - 本期相关 CVE 列表

🆕 新发现模式用 [NEW] 标识，并附自动提取的特征说明。

用法:
    python3 scripts/generate_digest.py --raw-file ./reports/raw/<date>/advisories.json \\
        --output-dir ./reports --format both
"""

import argparse
import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import VULN_CATEGORIES, TrackerConfig

try:
    from pattern_analyzer import (
        get_discovered_patterns,
        PATTERN_VULN_FEATURES,
        PATTERN_DEFENSE_POINTS,
        _pattern_display_name,
    )
    _ANALYZER_AVAILABLE = True
except ImportError:
    _ANALYZER_AVAILABLE = False

# ---------------------------------------------------------------------------
# 颜色 / 样式常量
# ---------------------------------------------------------------------------

SEVERITY_COLORS = {
    "CRITICAL": "#b71c1c",
    "HIGH":     "#e65100",
    "MEDIUM":   "#f57f17",
    "LOW":      "#1b5e20",
    "UNKNOWN":  "#546e7a",
}
CATEGORY_COLORS = {
    "G-INJ":    "#880e4f",  "G-AUTH":   "#1a237e",  "G-DOS":    "#b71c1c",
    "G-MEM":    "#4a148c",  "G-PROTO":  "#006064",  "G-CRYPTO": "#1b5e20",
    "G-SSRF":   "#e65100",  "G-PATH":   "#33691e",  "G-RACE":   "#bf360c",
    "G-SUPPLY": "#212121",  "G-OTHER":  "#546e7a",
}
NEW_COLOR = "#7b1fa2"   # 新发现模式紫色
NEW_BADGE = "🆕 [NEW]"

SEV_ICONS = {"CRITICAL":"🔴","HIGH":"🟠","MEDIUM":"🟡","LOW":"🟢","UNKNOWN":"⚪"}


# ---------------------------------------------------------------------------
# 辅助
# ---------------------------------------------------------------------------

def _h(text: str) -> str:
    return str(text).replace("&","&amp;").replace("<","&lt;").replace(">","&gt;").replace('"',"&quot;")

def _sev_badge_html(sev: str) -> str:
    c = SEVERITY_COLORS.get(sev, "#546e7a")
    return f'<span class="badge" style="background:{c}">{_h(sev)}</span>'

def _cat_color(cat: str) -> str:
    if cat.startswith("G-NEW-"):
        return NEW_COLOR
    return CATEGORY_COLORS.get(cat, "#546e7a")

def _cat_label(cat: str) -> str:
    if _ANALYZER_AVAILABLE:
        return _pattern_display_name(cat)
    return VULN_CATEGORIES.get(cat, cat)

def _is_new_pattern(cat: str) -> bool:
    return cat.startswith("G-NEW-")

def _get_pkg(v: dict) -> str:
    for a in v.get("affected", []):
        p = a.get("package") or ""
        if p:
            return p
    raw = v.get("_raw", {})
    for vp in raw.get("vulnerabilities", []):
        p = vp.get("package", {}).get("name", "")
        if p:
            return p
    return (v.get("id") or "")[:40]

def _get_fix(v: dict) -> str:
    for a in v.get("affected", []):
        for fv in a.get("fixed_versions", []):
            if isinstance(fv, dict) and fv.get("fixed"):
                return fv["fixed"]
        fa = a.get("fixed_at")
        if fa:
            return str(fa)
    return ""

def _get_vuln_range(v: dict) -> str:
    for a in v.get("affected", []):
        r = a.get("vulnerable_version_range", "")
        if r:
            return r
        for fv in a.get("fixed_versions", []):
            if isinstance(fv, dict) and fv.get("fixed"):
                return f"< {fv['fixed']}"
    return "—"

def _ref_url(v: dict) -> str:
    for r in v.get("references", []):
        if r and r.startswith("http"):
            return r
    return "#"


# ---------------------------------------------------------------------------
# 数据加载
# ---------------------------------------------------------------------------

def load_raw(raw_file: str) -> dict:
    with open(raw_file, encoding="utf-8") as f:
        return json.load(f)


def _group_by_pattern(advisories: list[dict]) -> dict[str, list[dict]]:
    """按漏洞模式分组，已知模式在前，新模式在后，G-OTHER 最末。"""
    groups: dict[str, list[dict]] = defaultdict(list)
    for v in advisories:
        groups[v.get("category", "G-OTHER")].append(v)

    order = list(VULN_CATEGORIES.keys()) + [
        k for k in groups if _is_new_pattern(k)
    ] + ["G-OTHER"]
    ordered = {}
    for cat in order:
        if cat in groups:
            # 每组内按严重度排序
            sev_o = {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3,"UNKNOWN":4}
            groups[cat].sort(key=lambda x: sev_o.get(x.get("severity","UNKNOWN"),4))
            ordered[cat] = groups[cat]
    return ordered


# ---------------------------------------------------------------------------
# Markdown 生成
# ---------------------------------------------------------------------------

def generate_markdown(data: dict, date_str: str) -> str:
    advisories = data.get("advisories", [])
    sev_counts  = data.get("severity_counts", {})
    total       = data.get("total", len(advisories))
    ts          = data.get("fetch_timestamp", "")[:19]
    groups      = _group_by_pattern(advisories)

    overall = ("CRITICAL" if sev_counts.get("CRITICAL",0) > 0 else
               "HIGH"     if sev_counts.get("HIGH",0) > 0 else
               "MEDIUM"   if sev_counts.get("MEDIUM",0) > 0 else "LOW")
    risk_icon = SEV_ICONS.get(overall, "⚪")

    new_patterns = [cat for cat in groups if _is_new_pattern(cat)]
    discovered   = get_discovered_patterns() if _ANALYZER_AVAILABLE else {}

    lines = []

    # ── 标题 ──────────────────────────────────────────────────
    lines += [
        f"# Go 开源项目安全分析报告 — {date_str}",
        "",
        f"> 生成时间: {ts} UTC  ",
        f"> 数据来源: Go 官方漏洞库 / OSV.dev / GitHub Security Advisories / NVD  ",
        f"> 分析维度: 漏洞模式特征 + 代码修改前后对比 + 防御方案",
        "",
    ]

    if new_patterns:
        lines += [
            f"> 🆕 **本期新发现漏洞模式 {len(new_patterns)} 个**: "
            + ", ".join(f"`{p}`" for p in new_patterns),
            "",
        ]

    lines += ["---", ""]

    # ── 执行摘要 ───────────────────────────────────────────────
    lines += [
        "## 执行摘要",
        "",
        f"| 指标 | 数值 |",
        f"|------|------|",
        f"| **今日漏洞总数** | {total} |",
        f"| **整体风险等级** | {risk_icon} **{overall}** |",
        f"| 🔴 CRITICAL | {sev_counts.get('CRITICAL',0)} |",
        f"| 🟠 HIGH | {sev_counts.get('HIGH',0)} |",
        f"| 🟡 MEDIUM | {sev_counts.get('MEDIUM',0)} |",
        f"| 🟢 LOW | {sev_counts.get('LOW',0)} |",
        f"| 🆕 新发现模式 | {len(new_patterns)} |",
        "",
    ]

    # 模式分布摘要
    if groups:
        lines += [
            "### 漏洞模式分布",
            "",
            "| 模式 | 名称 | 数量 | 最高严重度 |",
            "|------|------|------|-----------|",
        ]
        for cat, vulns in groups.items():
            label = _cat_label(cat)
            new_flag = " 🆕" if _is_new_pattern(cat) else ""
            top_sev = next((v.get("severity","") for v in vulns
                            if v.get("severity") in ("CRITICAL","HIGH")),
                           vulns[0].get("severity","") if vulns else "")
            sev_icon = SEV_ICONS.get(top_sev, "⚪")
            lines.append(f"| `{cat}`{new_flag} | {label} | {len(vulns)} | {sev_icon} {top_sev} |")
        lines += ["", "---", ""]

    # ── 漏洞模式详细分析 ────────────────────────────────────────
    lines += ["## 漏洞模式详细分析", ""]

    for cat, vulns in groups.items():
        if cat == "G-OTHER":
            continue  # G-OTHER 放到附录

        label    = _cat_label(cat)
        is_new   = _is_new_pattern(cat)
        new_flag = f" {NEW_BADGE}" if is_new else ""
        color_flag = "🆕 " if is_new else ""
        high_count = sum(1 for v in vulns if v.get("severity") in ("CRITICAL","HIGH"))

        lines += [
            f"### {color_flag}`{cat}` — {label}{new_flag}",
            "",
        ]

        # 新模式说明
        if is_new and cat in discovered:
            dp = discovered[cat]
            lines += [
                f"> **新发现模式说明**: {dp.description or '从本期漏洞自动识别的新模式'}  ",
                f"> 首次发现于: `{dp.first_seen}` ({dp.first_date}) | 本期出现: {len(vulns)} 次  ",
                f"> 关键特征词: {', '.join(f'`{k}`' for k in dp.keywords[:6])}",
                "",
            ]

        lines += [
            f"**本期漏洞数**: {len(vulns)} 条（CRITICAL/HIGH: {high_count} 条）",
            "",
        ]

        # ── 漏洞特征 ──
        lines += ["#### 漏洞特征", ""]

        # 聚合本组漏洞的 characteristics
        all_features = []
        for v in vulns:
            char = v.get("characteristics", {})
            for feat in char.get("vuln_features", []):
                if feat not in all_features:
                    all_features.append(feat)

        if all_features:
            for feat in all_features[:5]:
                lines.append(f"- {feat}")
        else:
            for feat in PATTERN_VULN_FEATURES.get(cat, ["参见漏洞描述"])[:4]:
                lines.append(f"- {feat}")
        lines.append("")

        # ── 触发条件 ──
        trigger_set = set()
        for v in vulns:
            for t in v.get("characteristics", {}).get("trigger_conditions", []):
                trigger_set.add(t)
        if trigger_set:
            lines += ["**触发条件**:", ""]
            for t in list(trigger_set)[:3]:
                lines.append(f"- {t}")
            lines.append("")

        # ── 代码修改前后对比 ──
        # 找到有 diff 的漏洞
        vuln_with_diff = [
            v for v in vulns
            if v.get("characteristics", {}).get("before_code")
               or v.get("characteristics", {}).get("after_code")
        ]

        if vuln_with_diff:
            lines += ["#### 代码修改对比（典型案例）", ""]
            # 选最严重的那条
            example = vuln_with_diff[0]
            char = example.get("characteristics", {})
            vid  = example.get("id") or example.get("cve_id") or ""
            fname = char.get("diff_filename", "")
            lines += [
                f"> 来源: `{vid}`"
                + (f" — `{fname}`" if fname else ""),
                "",
            ]
            if char.get("before_code"):
                lines += [
                    "**修改前（存在漏洞）**:",
                    "```go",
                    char["before_code"],
                    "```",
                    "",
                ]
            if char.get("after_code"):
                lines += [
                    "**修改后（已修复）**:",
                    "```go",
                    char["after_code"],
                    "```",
                    "",
                ]
        else:
            # 无 diff 时从模式库提供示例
            lines += _pattern_code_example_md(cat)

        # ── 防御方案 ──
        lines += ["#### 防御方案", ""]

        all_defense = []
        for v in vulns:
            for d in v.get("characteristics", {}).get("defense_points", []):
                if d not in all_defense:
                    all_defense.append(d)

        if all_defense:
            for d in all_defense[:5]:
                lines.append(f"- {d}")
        else:
            for d in PATTERN_DEFENSE_POINTS.get(cat, ["参见 references/go_vuln_patterns.md"])[:4]:
                lines.append(f"- {d}")
        lines.append("")

        # ── 本期相关漏洞 ──
        lines += [f"#### 本期相关漏洞（{len(vulns)} 条）", ""]
        lines += [
            "| 编号 | 受影响包 | 严重度 | 修复版本 | 摘要 |",
            "|------|---------|--------|---------|------|",
        ]
        for v in vulns[:15]:
            vid  = v.get("id") or v.get("cve_id") or v.get("ghsa_id") or "N/A"
            pkg  = _get_pkg(v)[:40]
            sev  = v.get("severity", "UNKNOWN")
            fix  = _get_fix(v) or "—"
            ttl  = (v.get("title") or "")[:55]
            url  = _ref_url(v)
            lines.append(f"| [`{vid}`]({url}) | `{pkg}` | {SEV_ICONS.get(sev,'')} {sev} | {fix} | {ttl} |")
        if len(vulns) > 15:
            lines.append(f"| ... | *（另有 {len(vulns)-15} 条）* | | | |")
        lines += ["", "---", ""]

    # ── 新模式汇总 ──
    if new_patterns:
        lines += [
            "## 🆕 新发现漏洞模式汇总",
            "",
            "以下模式为本期自动识别，不在预定义的 10 类模式库中，已自动补充到本地模式库：",
            "",
            "| 模式 ID | 名称 | 首见漏洞 | 关键特征词 |",
            "|---------|------|---------|----------|",
        ]
        for cat in new_patterns:
            dp = discovered.get(cat)
            if dp:
                kws = ", ".join(f"`{k}`" for k in dp.keywords[:5])
                lines.append(f"| `{cat}` | {dp.name_zh} | `{dp.first_seen}` | {kws} |")
            else:
                lines.append(f"| `{cat}` | 新模式 | — | — |")
        lines += [
            "",
            "> 模式库保存路径: `~/.go-security-tracker/discovered_patterns.json`",
            "",
            "---",
            "",
        ]

    # ── 全部漏洞按严重度列表 ──
    lines += ["## 漏洞列表（按严重度）", ""]
    crit_high = [v for v in advisories if v.get("severity") in ("CRITICAL","HIGH")]
    if crit_high:
        lines += [
            "### 🔴🟠 CRITICAL / HIGH",
            "",
            "| 编号 | 受影响包 | 严重度 | 模式 | CVSS | 修复版本 | 摘要 |",
            "|------|---------|--------|------|------|---------|------|",
        ]
        for v in crit_high[:30]:
            vid  = v.get("id") or v.get("cve_id") or "N/A"
            pkg  = _get_pkg(v)[:35]
            sev  = v.get("severity","UNKNOWN")
            cat  = v.get("category","G-OTHER")
            cvss = v.get("cvss_score") or "—"
            fix  = _get_fix(v) or "—"
            ttl  = (v.get("title") or "")[:50]
            new_f = " 🆕" if _is_new_pattern(cat) else ""
            url  = _ref_url(v)
            lines.append(
                f"| [`{vid}`]({url}) | `{pkg}` | {SEV_ICONS.get(sev,'')} {sev} "
                f"| `{cat}`{new_f} | {cvss} | {fix} | {ttl} |"
            )
        lines.append("")

    # ── 依赖升级清单 ──
    fixable = [v for v in advisories
               if _get_fix(v) and v.get("severity") in ("CRITICAL","HIGH")]
    if fixable:
        lines += [
            "## 依赖升级清单（CRITICAL/HIGH 有修复版本）",
            "",
            "| 包名 | 受影响版本 | 升级到 | 严重度 | 编号 |",
            "|------|-----------|-------|--------|------|",
        ]
        seen_pkgs: set[str] = set()
        for v in fixable[:25]:
            pkg = _get_pkg(v)
            if pkg in seen_pkgs:
                continue
            seen_pkgs.add(pkg)
            fix  = _get_fix(v)
            sev  = v.get("severity","UNKNOWN")
            vid  = v.get("cve_id") or v.get("ghsa_id") or v.get("id") or "N/A"
            vr   = _get_vuln_range(v)
            lines.append(f"| `{pkg}` | {vr} | **{fix}** | {sev} | `{vid}` |")
        lines.append("")

    # ── G-OTHER ──
    other = groups.get("G-OTHER", [])
    if other:
        lines += [
            "## 附录：未分类漏洞（G-OTHER）",
            "",
            f"共 {len(other)} 条，置信度不足以归入已有模式：",
            "",
            "| 编号 | 包 | 严重度 | 摘要 |",
            "|------|---|--------|------|",
        ]
        for v in other[:20]:
            vid = v.get("id") or v.get("cve_id") or "N/A"
            pkg = _get_pkg(v)[:30]
            sev = v.get("severity","UNKNOWN")
            ttl = (v.get("title") or "")[:55]
            lines.append(f"| `{vid}` | `{pkg}` | {SEV_ICONS.get(sev,'')} {sev} | {ttl} |")
        lines.append("")

    return "\n".join(lines)


def _pattern_code_example_md(cat: str) -> list[str]:
    """当无实际 diff 时，从参考库提供代码对比示例。"""
    examples = {
        "G-AUTH": [
            "**典型漏洞模式（修改前）**:",
            "```go",
            "// 未校验 JWT 算法类型",
            'token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {',
            '    return secretKey, nil  // 未检查 t.Method 类型！',
            '})',
            "```",
            "",
            "**修复后**:",
            "```go",
            "token, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {",
            '    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {',
            '        return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])',
            "    }",
            "    return secretKey, nil",
            "})",
            "```",
            "",
        ],
        "G-DOS": [
            "**典型漏洞模式（修改前）**:",
            "```go",
            "// HTTP handler 未限制请求体大小",
            "body, _ := io.ReadAll(r.Body)  // 可被大文件耗尽内存",
            "```",
            "",
            "**修复后**:",
            "```go",
            "r.Body = http.MaxBytesReader(w, r.Body, 10<<20)  // 限制 10MB",
            "body, err := io.ReadAll(r.Body)",
            "```",
            "",
        ],
        "G-PATH": [
            "**典型漏洞模式（修改前）**:",
            "```go",
            "// filepath.Join 可被绝对路径绕过",
            "fullPath := filepath.Join(baseDir, userInput)",
            "http.ServeFile(w, r, fullPath)  // 危险！",
            "```",
            "",
            "**修复后**:",
            "```go",
            "clean := filepath.Clean(userInput)",
            "rel, err := filepath.Rel(baseDir, filepath.Join(baseDir, clean))",
            'if err != nil || strings.HasPrefix(rel, "..") {',
            '    http.Error(w, "forbidden", 403); return',
            "}",
            "```",
            "",
        ],
        "G-SSRF": [
            "**典型漏洞模式（修改前）**:",
            "```go",
            "// 直接使用用户输入 URL",
            "resp, _ := http.Get(req.FormValue(\"url\"))  // 可访问内网！",
            "```",
            "",
            "**修复后**:",
            "```go",
            "// 使用自定义 Transport 过滤私有地址",
            "client := newSafeHTTPClient()  // 过滤 10.x / 172.x / 192.168.x / 169.254.x",
            "resp, err := client.Get(validatedURL)",
            "```",
            "",
        ],
        "G-CRYPTO": [
            "**典型漏洞模式（修改前）**:",
            "```go",
            "// 使用不安全的随机数",
            "token := fmt.Sprintf(\"%d\", rand.Int63())  // math/rand 可预测！",
            "```",
            "",
            "**修复后**:",
            "```go",
            "b := make([]byte, 32)",
            "if _, err := crand.Read(b); err != nil { ... }  // crypto/rand",
            "token := hex.EncodeToString(b)",
            "```",
            "",
        ],
    }
    return examples.get(cat, [])


# ---------------------------------------------------------------------------
# HTML 生成
# ---------------------------------------------------------------------------

def generate_html(data: dict, date_str: str) -> str:
    advisories = data.get("advisories", [])
    sev_counts  = data.get("severity_counts", {})
    total       = data.get("total", len(advisories))
    ts          = data.get("fetch_timestamp", "")[:19]
    groups      = _group_by_pattern(advisories)

    overall = ("CRITICAL" if sev_counts.get("CRITICAL",0) > 0 else
               "HIGH"     if sev_counts.get("HIGH",0) > 0 else
               "MEDIUM"   if sev_counts.get("MEDIUM",0) > 0 else "LOW")
    risk_color   = SEVERITY_COLORS.get(overall, "#546e7a")
    new_patterns = [cat for cat in groups if _is_new_pattern(cat)]
    discovered   = get_discovered_patterns() if _ANALYZER_AVAILABLE else {}

    # ── 导航链接 ──────────────────────────────────────────────
    nav_links = "".join(
        f'<a href="#pat-{cat}">'
        f'{"🆕 " if _is_new_pattern(cat) else ""}'
        f'{_cat_label(cat)} ({len(vulns)})</a>'
        for cat, vulns in groups.items()
        if cat != "G-OTHER"
    )

    # ── 模式摘要卡片 ─────────────────────────────────────────
    pattern_cards = ""
    for cat, vulns in groups.items():
        color = _cat_color(cat)
        label = _cat_label(cat)
        is_new = _is_new_pattern(cat)
        high_cnt = sum(1 for v in vulns if v.get("severity") in ("CRITICAL","HIGH"))
        pattern_cards += f"""
        <div class="pat-card" onclick="location.href='#pat-{_h(cat)}'">
          <div class="pat-card-header" style="background:{color}">
            <span class="pat-id">{_h(cat)}</span>
            {"<span class='new-badge'>NEW</span>" if is_new else ""}
          </div>
          <div class="pat-card-body">
            <div class="pat-name">{_h(label)}</div>
            <div class="pat-count">{len(vulns)} 条</div>
            <div class="pat-high">{'⚠ ' + str(high_cnt) + ' CRITICAL/HIGH' if high_cnt else '无高危'}</div>
          </div>
        </div>"""

    # ── 模式详情块 ─────────────────────────────────────────────
    pattern_sections = ""
    for cat, vulns in groups.items():
        if cat == "G-OTHER":
            continue

        color   = _cat_color(cat)
        label   = _cat_label(cat)
        is_new  = _is_new_pattern(cat)
        dp      = discovered.get(cat) if is_new else None

        # 聚合特征
        all_features: list[str] = []
        all_triggers: list[str] = []
        all_defense:  list[str] = []
        for v in vulns:
            char = v.get("characteristics", {})
            for f in char.get("vuln_features", []):
                if f not in all_features: all_features.append(f)
            for t in char.get("trigger_conditions", []):
                if t not in all_triggers: all_triggers.append(t)
            for d in char.get("defense_points", []):
                if d not in all_defense: all_defense.append(d)

        if not all_features:
            all_features = PATTERN_VULN_FEATURES.get(cat, [])
        if not all_defense:
            all_defense = PATTERN_DEFENSE_POINTS.get(cat, [])

        feature_items = "".join(f"<li>{_h(f)}</li>" for f in all_features[:5])
        trigger_items = "".join(f"<li>{_h(t)}</li>" for t in all_triggers[:3])
        defense_items = "".join(f"<li>{_h(d)}</li>" for d in all_defense[:5])

        # 代码 diff（找第一个有 diff 的漏洞）
        diff_section = ""
        vuln_with_diff = [v for v in vulns
                          if v.get("characteristics", {}).get("before_code")
                          or v.get("characteristics", {}).get("after_code")]
        if vuln_with_diff:
            ex = vuln_with_diff[0]
            char = ex.get("characteristics", {})
            vid_ex = _h(ex.get("id") or ex.get("cve_id") or "")
            fname  = _h(char.get("diff_filename",""))
            before = _h(char.get("before_code",""))
            after  = _h(char.get("after_code",""))
            diff_section = f"""
            <div class="diff-block">
              <div class="diff-title">代码修改对比 — <code>{vid_ex}</code> {('— '+fname) if fname else ''}</div>
              <div class="diff-grid">
                <div class="diff-col">
                  <div class="diff-col-header before-header">⚠ 修改前（存在漏洞）</div>
                  <pre class="diff-code before-code">{before}</pre>
                </div>
                <div class="diff-col">
                  <div class="diff-col-header after-header">✓ 修改后（已修复）</div>
                  <pre class="diff-code after-code">{after}</pre>
                </div>
              </div>
            </div>"""
        else:
            # 无实际 diff，使用模式库示例
            eg_lines = _pattern_code_example_md(cat)
            if eg_lines:
                before_lines: list[str] = []
                after_lines:  list[str] = []
                in_before = False; in_after = False
                for ln in eg_lines:
                    if "修改前" in ln: in_before = True; in_after = False; continue
                    if "修改后" in ln: in_after = True; in_before = False; continue
                    if ln.startswith("```"): continue
                    if in_before: before_lines.append(ln)
                    elif in_after: after_lines.append(ln)
                before_code = _h("\n".join(before_lines))
                after_code  = _h("\n".join(after_lines))
                diff_section = f"""
            <div class="diff-block">
              <div class="diff-title">典型代码模式示例（来自模式库）</div>
              <div class="diff-grid">
                <div class="diff-col">
                  <div class="diff-col-header before-header">⚠ 漏洞代码模式</div>
                  <pre class="diff-code before-code">{before_code}</pre>
                </div>
                <div class="diff-col">
                  <div class="diff-col-header after-header">✓ 修复代码模式</div>
                  <pre class="diff-code after-code">{after_code}</pre>
                </div>
              </div>
            </div>"""

        # 本期相关漏洞表格
        vuln_rows = ""
        for v in vulns[:20]:
            vid  = _h(v.get("id") or v.get("cve_id") or v.get("ghsa_id") or "N/A")
            pkg  = _h(_get_pkg(v)[:40])
            sev  = v.get("severity","UNKNOWN")
            fix  = _h(_get_fix(v) or "—")
            ttl  = _h((v.get("title") or "")[:70])
            url  = _h(_ref_url(v))
            cvss = v.get("cvss_score") or "—"
            conf = v.get("category_confidence", 0)
            vuln_rows += f"""
            <tr>
              <td><a href="{url}" target="_blank"><code>{vid}</code></a></td>
              <td><code>{pkg}</code></td>
              <td>{_sev_badge_html(sev)}</td>
              <td>{fix}</td>
              <td class="num">{cvss}</td>
              <td class="num">{conf:.2f}</td>
              <td class="desc">{ttl}</td>
            </tr>"""

        # 新模式说明框
        new_info = ""
        if is_new and dp:
            kws = ", ".join(f"<code>{_h(k)}</code>" for k in dp.keywords[:6])
            new_info = f"""
            <div class="new-pattern-info">
              <div class="new-pattern-title">🆕 新发现模式 — 自动识别说明</div>
              <p><strong>描述</strong>: {_h(dp.description or '从本期漏洞自动识别')}</p>
              <p><strong>首次发现</strong>: <code>{_h(dp.first_seen)}</code> ({_h(dp.first_date)})</p>
              <p><strong>关键特征词</strong>: {kws}</p>
              <p><strong>本期出现次数</strong>: {len(vulns)}</p>
              <p class="muted">此模式已自动追加到本地模式库 ~/.go-security-tracker/discovered_patterns.json</p>
            </div>"""

        pattern_sections += f"""
        <section class="pattern-section" id="pat-{_h(cat)}">
          <div class="pattern-header" style="border-left:5px solid {color}">
            <div class="pattern-title-row">
              <span class="pattern-id-badge" style="background:{color}">{_h(cat)}</span>
              <h2 class="pattern-name">{_h(label)}
                {"<span class='new-tag'>🆕 NEW</span>" if is_new else ""}
              </h2>
              <span class="pattern-count">{len(vulns)} 条</span>
            </div>
          </div>
          {new_info}

          <div class="pattern-body">
            <div class="analysis-grid">

              <div class="analysis-col">
                <div class="analysis-card">
                  <h3 class="card-title vuln-title">⚠ 漏洞特征</h3>
                  <ul class="feature-list">{feature_items}</ul>
                </div>
                {"<div class='analysis-card trigger-card'><h3 class='card-title'>触发条件</h3><ul class='feature-list'>" + trigger_items + "</ul></div>" if trigger_items else ""}
              </div>

              <div class="analysis-col">
                <div class="analysis-card">
                  <h3 class="card-title defense-title">🛡 防御方案</h3>
                  <ul class="feature-list defense-list">{defense_items}</ul>
                </div>
              </div>

            </div>

            {diff_section}

            <div class="vuln-table-wrapper">
              <h3>本期相关漏洞（{len(vulns)} 条）</h3>
              <table>
                <thead>
                  <tr><th>编号</th><th>受影响包</th><th>严重度</th><th>修复版本</th>
                      <th>CVSS</th><th>置信度</th><th>摘要</th></tr>
                </thead>
                <tbody>{vuln_rows}</tbody>
              </table>
              {"<p class='muted'>…另有 " + str(len(vulns)-20) + " 条，见原始 JSON</p>" if len(vulns)>20 else ""}
            </div>
          </div>
        </section>"""

    # ── 依赖升级清单 ──────────────────────────────────────────
    fixable = [v for v in advisories
               if _get_fix(v) and v.get("severity") in ("CRITICAL","HIGH")]
    upgrade_rows = ""
    seen_pkgs: set[str] = set()
    for v in fixable[:30]:
        pkg = _get_pkg(v)
        if pkg in seen_pkgs: continue
        seen_pkgs.add(pkg)
        fix  = _h(_get_fix(v))
        sev  = v.get("severity","UNKNOWN")
        vid  = _h(v.get("cve_id") or v.get("ghsa_id") or v.get("id") or "N/A")
        vr   = _h(_get_vuln_range(v))
        upgrade_rows += f"""
        <tr>
          <td><code>{_h(pkg)}</code></td>
          <td><code>{vr}</code></td>
          <td><strong>{fix}</strong></td>
          <td>{_sev_badge_html(sev)}</td>
          <td><code>{vid}</code></td>
        </tr>"""

    upgrade_section = f"""
    <section id="upgrade">
      <h2>依赖升级清单</h2>
      <p class="muted">以下 CRITICAL/HIGH 漏洞已有修复版本，建议立即升级：</p>
      {"<p class='muted'>本期无高危可修复漏洞。</p>" if not upgrade_rows else
       "<table><thead><tr><th>包名</th><th>受影响版本</th><th>升级到</th><th>严重度</th><th>编号</th></tr></thead><tbody>"
       + upgrade_rows + "</tbody></table>"}
    </section>"""

    # ── 新模式汇总 ────────────────────────────────────────────
    new_summary = ""
    if new_patterns:
        rows = ""
        for cat in new_patterns:
            dp = discovered.get(cat)
            if dp:
                kws = ", ".join(f"<code>{_h(k)}</code>" for k in dp.keywords[:5])
                rows += f"<tr><td><code>{_h(cat)}</code></td><td>{_h(dp.name_zh)}</td><td><code>{_h(dp.first_seen)}</code></td><td>{kws}</td></tr>"
        new_summary = f"""
    <section id="new-patterns">
      <h2>🆕 新发现漏洞模式汇总</h2>
      <p>以下模式为本期自动识别，已自动追加到本地模式库：</p>
      <table>
        <thead><tr><th>模式 ID</th><th>名称</th><th>首见漏洞</th><th>关键特征词</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
      <p class="muted">模式库路径: <code>~/.go-security-tracker/discovered_patterns.json</code></p>
    </section>"""

    # ── CSS & JS ──────────────────────────────────────────────
    css = f"""
    :root {{
      --font: -apple-system, BlinkMacSystemFont, 'PingFang SC', 'Microsoft YaHei', sans-serif;
      --bg: #f4f6f8; --card: #fff; --border: #dde3ec; --text: #1a202c; --muted: #718096;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.7; font-size: 14px; }}
    header {{ background: #1a1a2e; color: white; padding: 1.4rem 2rem; border-bottom: 4px solid {risk_color}; }}
    header h1 {{ font-size: 1.4rem; }} header .meta {{ color: #b0bec5; font-size: 0.8rem; margin-top: 0.2rem; }}
    nav {{ background: #16213e; padding: 0.4rem 2rem; display: flex; gap: 1rem; flex-wrap: wrap; overflow-x: auto; }}
    nav a {{ color: #90caf9; text-decoration: none; font-size: 0.8rem; white-space: nowrap; padding: 0.2rem 0; }}
    nav a:hover {{ color: white; }}
    main {{ max-width: 1280px; margin: 0 auto; padding: 1.5rem; }}
    section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.2rem 1.5rem; margin-bottom: 1.5rem; }}
    h2 {{ font-size: 1.1rem; margin-bottom: 0.8rem; padding-bottom: 0.4rem; border-bottom: 2px solid var(--border); }}
    h3 {{ font-size: 0.95rem; margin: 0.7rem 0 0.4rem; }}
    /* 模式卡片网格 */
    .pattern-cards {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px,1fr)); gap: 0.8rem; }}
    .pat-card {{ border: 1px solid var(--border); border-radius: 6px; overflow: hidden; cursor: pointer; transition: box-shadow .2s; }}
    .pat-card:hover {{ box-shadow: 0 4px 12px rgba(0,0,0,.12); }}
    .pat-card-header {{ color: white; padding: 0.4rem 0.7rem; display: flex; justify-content: space-between; align-items: center; }}
    .pat-id {{ font-weight: 700; font-size: 0.78rem; }}
    .new-badge {{ background: rgba(255,255,255,.25); padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.68rem; }}
    .pat-card-body {{ padding: 0.5rem 0.7rem; }}
    .pat-name {{ font-size: 0.8rem; font-weight: 600; }}
    .pat-count {{ font-size: 0.75rem; color: var(--muted); }}
    .pat-high {{ font-size: 0.72rem; color: {SEVERITY_COLORS["HIGH"]}; margin-top: 0.2rem; }}
    /* 模式详情 */
    .pattern-section {{ padding: 0; overflow: hidden; }}
    .pattern-header {{ padding: 0.8rem 1.2rem; background: #fafafa; border-bottom: 1px solid var(--border); }}
    .pattern-title-row {{ display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap; }}
    .pattern-id-badge {{ color: white; padding: 0.2rem 0.6rem; border-radius: 4px; font-size: 0.8rem; font-weight: 700; }}
    .pattern-name {{ font-size: 1.05rem; font-weight: 600; }}
    .new-tag {{ background: {NEW_COLOR}; color: white; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.72rem; margin-left: 0.5rem; }}
    .pattern-count {{ color: var(--muted); font-size: 0.85rem; margin-left: auto; }}
    .pattern-body {{ padding: 1rem 1.2rem; }}
    /* 分析网格 */
    .analysis-grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 1rem; margin-bottom: 1rem; }}
    @media (max-width: 768px) {{ .analysis-grid {{ grid-template-columns: 1fr; }} }}
    .analysis-card {{ background: #fafafa; border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem; }}
    .card-title {{ font-size: 0.88rem; font-weight: 700; margin-bottom: 0.5rem; }}
    .vuln-title {{ color: {SEVERITY_COLORS["HIGH"]}; }}
    .defense-title {{ color: #1b5e20; }}
    .feature-list {{ list-style: disc; padding-left: 1.2rem; font-size: 0.83rem; line-height: 1.8; }}
    .defense-list li {{ color: #1b5e20; }}
    /* Code diff */
    .diff-block {{ margin: 0.8rem 0; border: 1px solid var(--border); border-radius: 6px; overflow: hidden; }}
    .diff-title {{ background: #eceff1; padding: 0.4rem 0.8rem; font-size: 0.8rem; font-weight: 600; color: #37474f; }}
    .diff-grid {{ display: grid; grid-template-columns: 1fr 1fr; }}
    @media (max-width: 900px) {{ .diff-grid {{ grid-template-columns: 1fr; }} }}
    .diff-col {{ overflow: hidden; }}
    .diff-col-header {{ padding: 0.3rem 0.8rem; font-size: 0.78rem; font-weight: 600; }}
    .before-header {{ background: #ffebee; color: {SEVERITY_COLORS["CRITICAL"]}; border-right: 1px solid #ffcdd2; }}
    .after-header  {{ background: #e8f5e9; color: #1b5e20; }}
    .diff-code {{ background: #263238; color: #cfd8dc; padding: 0.8rem; font-size: 0.78rem; line-height: 1.6; overflow-x: auto; min-height: 60px; white-space: pre; }}
    .before-code {{ border-right: 2px solid {SEVERITY_COLORS["CRITICAL"]}; }}
    .after-code {{ border-left: 2px solid #1b5e20; }}
    /* Vuln table */
    .vuln-table-wrapper {{ margin-top: 0.8rem; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.82rem; margin-top: 0.5rem; }}
    th {{ background: #eceff1; text-align: left; padding: 0.5rem 0.6rem; border: 1px solid var(--border); white-space: nowrap; }}
    td {{ padding: 0.4rem 0.6rem; border: 1px solid var(--border); vertical-align: middle; }}
    tr:hover {{ background: #f8f9fa; }}
    td.desc {{ max-width: 260px; color: var(--muted); }}
    td.num {{ text-align: center; }}
    code {{ background: #e8eaf6; padding: 0.1rem 0.35rem; border-radius: 3px; font-size: 0.8rem; }}
    a {{ color: #1565c0; }}
    .badge {{ display: inline-block; color: white; padding: 0.15rem 0.5rem; border-radius: 3px; font-size: 0.72rem; font-weight: 600; }}
    .muted {{ color: var(--muted); font-size: 0.82rem; margin-top: 0.4rem; }}
    /* 新模式信息框 */
    .new-pattern-info {{ background: #f3e5f5; border: 1px solid #ce93d8; border-left: 4px solid {NEW_COLOR}; padding: 0.8rem 1rem; margin: 0.8rem 1.2rem; border-radius: 4px; font-size: 0.84rem; }}
    .new-pattern-title {{ font-weight: 700; color: {NEW_COLOR}; margin-bottom: 0.4rem; }}
    /* Stats */
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(120px,1fr)); gap: 0.8rem; }}
    .stat-card {{ background: var(--bg); border: 1px solid var(--border); border-radius: 6px; padding: 0.8rem; text-align: center; }}
    .stat-card .value {{ font-size: 1.6rem; font-weight: 700; }}
    .stat-card .label {{ font-size: 0.7rem; color: var(--muted); text-transform: uppercase; }}
    .risk-pill {{ background: {risk_color}; color: white; padding: 0.2rem 0.8rem; border-radius: 4px; font-weight: 700; font-size: 1rem; }}
    footer {{ text-align: center; color: var(--muted); font-size: 0.75rem; padding: 1.5rem; }}
    """

    html = f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>Go 安全分析报告 — {_h(date_str)}</title>
  <style>{css}</style>
</head>
<body>
<header>
  <h1>🔐 Go 开源项目安全分析报告</h1>
  <div class="meta">
    日期: <strong>{_h(date_str)}</strong> &nbsp;|&nbsp;
    生成: <strong>{_h(ts)} UTC</strong> &nbsp;|&nbsp;
    分析维度: 漏洞模式特征 · 代码修改对比 · 防御方案
    {"&nbsp;|&nbsp;<strong style='color:#ce93d8'>🆕 " + str(len(new_patterns)) + " 个新模式</strong>" if new_patterns else ""}
  </div>
</header>
<nav>
  <a href="#summary">执行摘要</a>
  {nav_links}
  {"<a href='#new-patterns'>🆕 新模式</a>" if new_patterns else ""}
  <a href="#upgrade">升级清单</a>
</nav>
<main>

  <section id="summary">
    <h2>执行摘要</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="value"><span class="risk-pill">{_h(overall)}</span></div>
        <div class="label">整体风险</div>
      </div>
      <div class="stat-card">
        <div class="value">{total}</div><div class="label">漏洞总数</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['CRITICAL']}">{sev_counts.get('CRITICAL',0)}</div>
        <div class="label">🔴 CRITICAL</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['HIGH']}">{sev_counts.get('HIGH',0)}</div>
        <div class="label">🟠 HIGH</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['MEDIUM']}">{sev_counts.get('MEDIUM',0)}</div>
        <div class="label">🟡 MEDIUM</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{NEW_COLOR}">{len(new_patterns)}</div>
        <div class="label">🆕 新模式</div>
      </div>
    </div>

    <h3 style="margin-top:1rem">漏洞模式分布</h3>
    <div class="pattern-cards" style="margin-top:0.6rem">{pattern_cards}</div>
  </section>

  {pattern_sections}

  {new_summary}

  {upgrade_section}

</main>
<footer>Go 安全分析报告 · 漏洞模式驱动 · {_h(date_str)}</footer>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# CLI 入口
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="生成 Go 安全日报（漏洞模式驱动）")
    parser.add_argument("--raw-file",   required=True, help="fetch_advisories.py 输出的 JSON 文件")
    parser.add_argument("--output-dir", default="./go-security-reports")
    parser.add_argument("--format",     choices=["html","markdown","both"], default="both")
    parser.add_argument("--date",       help="报告日期 YYYY-MM-DD")
    args = parser.parse_args()

    raw_file   = Path(args.raw_file)
    if not raw_file.exists():
        print(f"ERROR: 找不到文件 {raw_file}", file=sys.stderr); sys.exit(1)

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    data     = load_raw(str(raw_file))
    date_str = args.date or data.get("date") or raw_file.parent.name \
               or datetime.now(timezone.utc).strftime("%Y-%m-%d")

    adv   = data.get("advisories", [])
    sev   = data.get("severity_counts", {})
    cats  = data.get("category_counts", {})
    total = data.get("total", len(adv))
    new_patterns = [c for c in cats if c.startswith("G-NEW-")]

    print(f"漏洞总数: {total}  CRITICAL={sev.get('CRITICAL',0)} HIGH={sev.get('HIGH',0)} "
          f"MEDIUM={sev.get('MEDIUM',0)} LOW={sev.get('LOW',0)}")
    print(f"漏洞模式: {len(cats)} 类  新模式: {len(new_patterns)} 个")

    reports = []
    if args.format in ("html", "both"):
        p = output_dir / f"go-security-digest-{date_str}.html"
        print("生成 HTML 日报（漏洞模式驱动）...")
        p.write_text(generate_html(data, date_str), encoding="utf-8")
        reports.append(str(p))
        print(f"  HTML: {p}")

    if args.format in ("markdown", "both"):
        p = output_dir / f"go-security-digest-{date_str}.md"
        print("生成 Markdown 日报（漏洞模式驱动）...")
        p.write_text(generate_markdown(data, date_str), encoding="utf-8")
        reports.append(str(p))
        print(f"  Markdown: {p}")

    overall = ("CRITICAL" if sev.get("CRITICAL",0) > 0 else
               "HIGH"     if sev.get("HIGH",0) > 0 else
               "MEDIUM"   if sev.get("MEDIUM",0) > 0 else "LOW")

    print(f"\n{'='*60}")
    print(f"Go 安全分析报告生成完成")
    print(f"{'='*60}")
    print(f"日期     : {date_str}")
    print(f"整体风险 : {overall}")
    print(f"漏洞总数 : {total}")
    if new_patterns:
        print(f"🆕 新模式 : {', '.join(new_patterns)}")
    print(f"报告文件 :")
    for r in reports:
        print(f"  {r}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
