#!/usr/bin/env python3
"""
Generate HTML and Markdown security reports from Trivy scan results.

Usage:
    python scripts/generate_report.py --raw-dir ./report/raw --output-dir ./report --image nginx:latest
    python scripts/generate_report.py --scan-json ./report/scan_results.json --output-dir ./report --image nginx:latest
    python scripts/generate_report.py --help
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4, "INFO": 5}
SEVERITY_COLORS = {
    "CRITICAL": "#d32f2f",
    "HIGH":     "#f57c00",
    "MEDIUM":   "#fbc02d",
    "LOW":      "#388e3c",
    "UNKNOWN":  "#757575",
    "INFO":     "#0288d1",
    "PASS":     "#2e7d32",
}
SEVERITY_BADGES = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH":     "🟠 HIGH",
    "MEDIUM":   "🟡 MEDIUM",
    "LOW":      "🟢 LOW",
    "UNKNOWN":  "⚪ UNKNOWN",
    "INFO":     "🔵 INFO",
    "PASS":     "✅ PASS",
}

CIS_DOCKER_CONTROLS = {
    "DS-0002": {
        "title": "Image user should not be 'root'",
        "level": "L1",
        "section": "4.1",
        "cis_id": "CIS 4.1",
    },
    "DS-0004": {
        "title": "Port 22 (SSH) should not be exposed",
        "level": "L1",
        "section": "5.x",
        "cis_id": "CIS 5.7",
    },
    "DS-0005": {
        "title": "ADD command used instead of COPY",
        "level": "L1",
        "section": "4.9",
        "cis_id": "CIS 4.9",
    },
    "DS-0013": {
        "title": "RUN using 'sudo' command",
        "level": "L1",
        "section": "4.1",
        "cis_id": "CIS 4.1",
    },
    "DS-0017": {
        "title": "'RUN <package-manager> update' instruction alone",
        "level": "L1",
        "section": "4.7",
        "cis_id": "CIS 4.7",
    },
    "DS-0020": {
        "title": "Last USER command in Dockerfile should not be 'root'",
        "level": "L1",
        "section": "4.1",
        "cis_id": "CIS 4.1",
    },
    "DS-0021": {
        "title": "Sensitive data stored in ENV (environment variable)",
        "level": "L1",
        "section": "4.10",
        "cis_id": "CIS 4.10",
    },
    "DS-0026": {
        "title": "No HEALTHCHECK defined",
        "level": "L1",
        "section": "4.6",
        "cis_id": "CIS 4.6",
    },
    "DS-0029": {
        "title": "'apt-get' missing '--no-install-recommends'",
        "level": "L1",
        "section": "4.3",
        "cis_id": "CIS 4.3",
    },
    "DS-0031": {
        "title": "Secrets passed via build-args, ENV, or copied secret files",
        "level": "L1",
        "section": "4.10",
        "cis_id": "CIS 4.10",
    },
    "DS-0032": {
        "title": "Specific version tag not used in FROM statement",
        "level": "L1",
        "section": "4.2",
        "cis_id": "CIS 4.2",
    },
    "DS-0025": {
        "title": "All images should use a non latest version tag",
        "level": "L1",
        "section": "4.2",
        "cis_id": "CIS 4.2",
    },
}


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_scan_data(raw_dir: str = None, scan_json: str = None) -> dict:
    if scan_json and os.path.isfile(scan_json):
        with open(scan_json, encoding="utf-8") as f:
            return json.load(f)

    if not raw_dir:
        raise ValueError("Either --raw-dir or --scan-json must be provided")

    raw = Path(raw_dir)
    data = {"summary": {}, "vulnerabilities": [], "misconfigurations": [], "secrets": []}

    vuln_file = raw / "vulnerabilities.json"
    misconfig_file = raw / "misconfigurations.json"
    secrets_file = raw / "secrets.json"

    # Import scan_image helpers inline
    sys.path.insert(0, str(Path(__file__).parent))
    from scan_image import (
        collect_all_vulnerabilities,
        collect_all_misconfigurations,
        collect_all_secrets,
        build_summary,
        extract_image_metadata,
    )

    vuln_data = {}
    misconfig_data = {}
    secret_data = {}

    if vuln_file.exists():
        with open(vuln_file, encoding="utf-8") as f:
            vuln_data = json.load(f)
    if misconfig_file.exists():
        with open(misconfig_file, encoding="utf-8") as f:
            misconfig_data = json.load(f)
    if secrets_file.exists():
        with open(secrets_file, encoding="utf-8") as f:
            secret_data = json.load(f)

    # summary may lack image name — caller passes it explicitly
    summary = build_summary("unknown", vuln_data, misconfig_data, secret_data)
    data["summary"] = summary
    data["vulnerabilities"] = collect_all_vulnerabilities(vuln_data.get("Results", []) or [])
    data["misconfigurations"] = collect_all_misconfigurations(misconfig_data.get("Results", []) or [])
    data["secrets"] = collect_all_secrets(secret_data.get("Results", []) if secret_data else [])
    return data


# ---------------------------------------------------------------------------
# Markdown report
# ---------------------------------------------------------------------------

def generate_markdown(data: dict, image: str) -> str:
    summary = data["summary"]
    vulns = data["vulnerabilities"]
    misconfigs = data["misconfigurations"]
    secrets = data.get("secrets", [])

    ts = summary.get("scan_timestamp", datetime.now(timezone.utc).isoformat())
    risk = summary.get("risk_rating", "UNKNOWN")
    cis = summary.get("cis_compliance", {})
    vc = summary.get("vulnerability_counts", {})
    mc = summary.get("misconfig_counts", {})
    meta = summary.get("image_metadata", {})

    lines = []

    # Header
    lines += [
        "# Container Image Security Report",
        "",
        f"**Image:** `{image}`  ",
        f"**Scan Date:** {ts[:19].replace('T', ' ')} UTC  ",
        f"**Scanner:** Trivy  ",
        f"**CIS Benchmark:** CIS Docker Benchmark v1.6  ",
        "",
        "---",
        "",
    ]

    # Executive Summary
    risk_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "PASS": "✅"}.get(risk, "⚪")
    lines += [
        "## Executive Summary",
        "",
        f"| | |",
        f"|---|---|",
        f"| **Overall Risk Rating** | {risk_emoji} **{risk}** |",
    ]

    if cis.get("total", 0) > 0:
        lines.append(
            f"| **CIS Benchmark Compliance** | "
            f"{cis.get('passed', 0)}/{cis.get('total', 0)} checks passed "
            f"({cis.get('score_pct', 0):.1f}%) |"
        )

    total_vulns = sum(vc.values())
    total_misconfigs = sum(mc.values())
    lines += [
        f"| **Total Vulnerabilities** | {total_vulns} |",
        f"| **Total Misconfigurations** | {total_misconfigs} |",
    ]
    if secrets:
        lines.append(f"| **Exposed Secrets** | ⚠️ {len(secrets)} found |")
    lines.append("")

    # Vulnerability counts table
    lines += [
        "### Vulnerability Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        count = vc.get(sev, 0)
        lines.append(f"| {sev} | {count} |")
    lines.append("")

    # Misconfiguration counts
    lines += [
        "### Misconfiguration Severity Breakdown",
        "",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"):
        count = mc.get(sev, 0)
        lines.append(f"| {sev} | {count} |")
    lines.append("")
    lines.append("---")
    lines.append("")

    # CIS Benchmark Section
    # CIS-relevant misconfigs are DS-XXXX checks from Trivy's Dockerfile scanner
    cis_misconfigs = [
        m for m in misconfigs
        if m.get("misconfig_id", "").startswith("DS-")
        or m.get("misconfig_id", "").startswith("CIS-")
    ]
    if cis_misconfigs:
        lines += [
            "## CIS Docker Benchmark Compliance (Container Image / Dockerfile Checks)",
            "",
            "| Control ID | CIS Ref | Description | Level | Status | Severity |",
            "|------------|---------|-------------|-------|--------|----------|",
        ]
        seen = {}
        for m in cis_misconfigs:
            mid = m.get("misconfig_id", "")
            if mid in seen:
                continue
            seen[mid] = True
            ctrl = CIS_DOCKER_CONTROLS.get(mid, {})
            level = ctrl.get("level", "L1")
            cis_ref = ctrl.get("cis_id", "—")
            status_emoji = "✅ PASS" if m.get("status") == "PASS" else "❌ FAIL"
            lines.append(
                f"| `{mid}` | {cis_ref} | {m.get('title', ctrl.get('title', ''))} "
                f"| {level} | {status_emoji} | {m.get('severity', '')} |"
            )
        lines.append("")
        lines.append("---")
        lines.append("")

    # Vulnerability Findings
    if vulns:
        lines += ["## Vulnerability Findings", ""]
        critical_high = [v for v in vulns if v.get("severity") in ("CRITICAL", "HIGH")]
        if critical_high:
            lines += [
                f"### ⚠️ Critical & High Severity ({len(critical_high)} findings)",
                "",
                "| CVE ID | Package | Version | Fix Version | CVSS | Severity |",
                "|--------|---------|---------|-------------|------|----------|",
            ]
            for v in critical_high[:50]:
                fix = v.get("fixed_version") or "No fix available"
                cvss = v.get("cvss_score") or "N/A"
                lines.append(
                    f"| [{v['vuln_id']}]({v.get('primary_url', '#')}) "
                    f"| `{v['pkg_name']}` | {v['installed_version']} "
                    f"| {fix} | {cvss} | **{v['severity']}** |"
                )
            lines.append("")

        medium_low = [v for v in vulns if v.get("severity") in ("MEDIUM", "LOW")]
        if medium_low:
            lines += [
                f"### Medium & Low Severity ({len(medium_low)} findings)",
                "",
                "| CVE ID | Package | Version | Fix Version | Severity |",
                "|--------|---------|---------|-------------|----------|",
            ]
            for v in medium_low[:30]:
                fix = v.get("fixed_version") or "No fix"
                lines.append(
                    f"| `{v['vuln_id']}` | `{v['pkg_name']}` "
                    f"| {v['installed_version']} | {fix} | {v['severity']} |"
                )
            if len(medium_low) > 30:
                lines.append(f"| ... | *(and {len(medium_low) - 30} more)* | | | |")
            lines.append("")
        lines.append("---")
        lines.append("")

    # Misconfiguration Findings
    fail_misconfigs = [m for m in misconfigs if m.get("status") != "PASS"]
    if fail_misconfigs:
        lines += [
            "## Misconfiguration Findings",
            "",
            "| ID | Title | Severity | Resolution |",
            "|----|-------|----------|------------|",
        ]
        for m in fail_misconfigs[:30]:
            resolution = (m.get("resolution") or "See references")[:80]
            lines.append(
                f"| `{m.get('misconfig_id', m.get('avd_id', ''))}` "
                f"| {m.get('title', '')} | {m.get('severity', '')} "
                f"| {resolution} |"
            )
        lines.append("")
        lines.append("---")
        lines.append("")

    # Secrets
    if secrets:
        lines += [
            "## ⚠️ Exposed Secrets",
            "",
            "> **ACTION REQUIRED**: Rotate all exposed credentials immediately.",
            "",
            "| File | Category | Title | Severity |",
            "|------|----------|-------|----------|",
        ]
        for s in secrets:
            lines.append(
                f"| `{s.get('target', '')}` | {s.get('category', '')} "
                f"| {s.get('title', '')} | **{s.get('severity', '')}** |"
            )
        lines.append("")
        lines.append("---")
        lines.append("")

    # Recommendations
    lines += [
        "## Recommendations",
        "",
        "Based on the scan findings, here are the prioritized remediation steps:",
        "",
    ]

    recommendations = _build_recommendations(data)
    for i, rec in enumerate(recommendations, 1):
        lines.append(f"{i}. **[{rec['priority']}]** {rec['action']}")
    lines.append("")
    lines.append("---")
    lines.append("")

    # Appendix
    lines += [
        "## Appendix",
        "",
        "### Scan Methodology",
        "",
        "This report was generated using **Trivy** by Aqua Security. The scanner checks:",
        "- **Vulnerabilities**: CVEs from NVD, OS vendor advisories (Ubuntu, Debian, Alpine, RHEL, etc.)",
        "- **Misconfigurations**: CIS Docker Benchmark Section 4 controls",
        "- **Secrets**: Pattern matching for API keys, passwords, tokens",
        "",
        "### CIS Docker Benchmark",
        "",
        "The CIS Docker Benchmark provides authoritative guidance for establishing a secure configuration posture.",
        "Controls are classified as Level 1 (basic security, minimal operational impact) or",
        "Level 2 (defense-in-depth, may impact usability).",
        "",
        "Reference: https://www.cisecurity.org/benchmark/docker",
        "",
    ]

    if meta:
        lines += [
            "### Image Metadata",
            "",
            f"- **Image ID**: `{meta.get('image_id', 'N/A')}`",
        ]
        os_info = meta.get("os", {})
        if os_info:
            lines.append(f"- **OS**: {os_info.get('Family', '')} {os_info.get('Name', '')}")
        tags = meta.get("repo_tags", [])
        if tags:
            lines.append(f"- **Tags**: {', '.join(tags)}")
        digests = meta.get("repo_digests", [])
        if digests:
            lines.append(f"- **Digest**: `{digests[0]}`")
        lines.append("")

    return "\n".join(lines)


def _build_recommendations(data: dict) -> list[dict]:
    recs = []
    vulns = data.get("vulnerabilities", [])
    misconfigs = data.get("misconfigurations", [])
    secrets = data.get("secrets", [])

    if secrets:
        recs.append({
            "priority": "CRITICAL",
            "action": "Rotate all exposed secrets/credentials immediately. Remove them from the image and use environment variables or secrets management tools (e.g., Vault, AWS Secrets Manager).",
        })

    crit_vulns = [v for v in vulns if v.get("severity") == "CRITICAL"]
    if crit_vulns:
        fixable = [v for v in crit_vulns if v.get("fixed_version")]
        recs.append({
            "priority": "CRITICAL",
            "action": f"Update {len(fixable)} packages with known CRITICAL CVE fixes: "
                      + ", ".join(f"`{v['pkg_name']}` → {v['fixed_version']}" for v in fixable[:5])
                      + (" (and more)" if len(fixable) > 5 else ""),
        })

    high_vulns = [v for v in vulns if v.get("severity") == "HIGH"]
    if high_vulns:
        fixable = [v for v in high_vulns if v.get("fixed_version")]
        recs.append({
            "priority": "HIGH",
            "action": f"Update {len(fixable)} packages with HIGH severity CVE fixes.",
        })

    non_root = next(
        (m for m in misconfigs
         if m.get("misconfig_id", "") in ("DS-0002", "DS-0020", "CIS-DI-0001")
         and m.get("status") == "FAIL"),
        None,
    )
    if non_root:
        recs.append({
            "priority": "HIGH",
            "action": "Add a non-root USER instruction to your Dockerfile (CIS 4.1 / DS-0002). Running containers as root significantly increases attack surface.",
        })

    secret_env = next(
        (m for m in misconfigs
         if m.get("misconfig_id", "") in ("DS-0031", "DS-0021", "CIS-DI-0010")
         and m.get("status") == "FAIL"),
        None,
    )
    if secret_env and not secrets:
        recs.append({
            "priority": "CRITICAL",
            "action": "Remove hardcoded secrets from ENV variables or build-args in your Dockerfile (CIS 4.10 / DS-0031). Use Docker secrets or a secrets manager instead.",
        })

    health_check = next(
        (m for m in misconfigs
         if m.get("misconfig_id", "") in ("DS-0026", "CIS-DI-0006")
         and m.get("status") == "FAIL"),
        None,
    )
    if health_check:
        recs.append({
            "priority": "MEDIUM",
            "action": "Add a HEALTHCHECK instruction to your Dockerfile (CIS 4.6 / DS-0026) to enable container health monitoring.",
        })

    add_instr = next(
        (m for m in misconfigs
         if m.get("misconfig_id", "") in ("DS-0005", "CIS-DI-0009")
         and m.get("status") == "FAIL"),
        None,
    )
    if add_instr:
        recs.append({
            "priority": "LOW",
            "action": "Replace ADD with COPY in your Dockerfile (CIS 4.9 / DS-0005). COPY is more transparent and predictable.",
        })

    total_vulns = sum(data.get("summary", {}).get("vulnerability_counts", {}).values())
    if total_vulns > 0:
        recs.append({
            "priority": "MEDIUM",
            "action": "Consider using a minimal base image (e.g., distroless, Alpine) to reduce the overall attack surface and number of vulnerable packages.",
        })

    recs.append({
        "priority": "LOW",
        "action": "Integrate this scanner into your CI/CD pipeline to catch vulnerabilities before deployment. Use `trivy image --exit-code 1 --severity CRITICAL` to fail builds with critical vulnerabilities.",
    })

    return recs


# ---------------------------------------------------------------------------
# HTML report
# ---------------------------------------------------------------------------

def generate_html(data: dict, image: str) -> str:
    summary = data["summary"]
    vulns = data["vulnerabilities"]
    misconfigs = data["misconfigurations"]
    secrets = data.get("secrets", [])

    ts = summary.get("scan_timestamp", datetime.now(timezone.utc).isoformat())
    risk = summary.get("risk_rating", "UNKNOWN")
    cis = summary.get("cis_compliance", {})
    vc = summary.get("vulnerability_counts", {})
    mc = summary.get("misconfig_counts", {})

    risk_color = SEVERITY_COLORS.get(risk, "#757575")
    cis_score = cis.get("score_pct")
    cis_bar_color = "#388e3c" if (cis_score or 0) >= 80 else "#f57c00" if (cis_score or 0) >= 60 else "#d32f2f"

    fail_misconfigs = [m for m in misconfigs if m.get("status") != "PASS"]
    recs = _build_recommendations(data)

    def sev_badge(sev: str) -> str:
        color = SEVERITY_COLORS.get(sev.upper(), "#757575")
        return f'<span class="badge" style="background:{color}">{sev}</span>'

    def status_badge(status: str) -> str:
        if status == "PASS":
            return '<span class="badge" style="background:#388e3c">✓ PASS</span>'
        return '<span class="badge" style="background:#d32f2f">✗ FAIL</span>'

    def h(text: str) -> str:
        """HTML-escape."""
        return str(text).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    # Vulnerability rows
    vuln_rows = ""
    for v in vulns[:200]:
        fix = h(v.get("fixed_version") or "—")
        cvss = v.get("cvss_score") or "—"
        url = h(v.get("primary_url") or "#")
        vuln_rows += f"""
        <tr>
          <td><a href="{url}" target="_blank">{h(v['vuln_id'])}</a></td>
          <td>{h(v['pkg_name'])}</td>
          <td>{h(v['installed_version'])}</td>
          <td>{fix}</td>
          <td>{cvss}</td>
          <td>{sev_badge(v['severity'])}</td>
          <td class="desc">{h(v.get('title', ''))}</td>
        </tr>"""

    # Misconfig rows
    misconfig_rows = ""
    for m in fail_misconfigs[:100]:
        resolution = h(m.get("resolution") or m.get("message") or "")
        misconfig_rows += f"""
        <tr>
          <td><code>{h(m.get('misconfig_id') or m.get('avd_id', ''))}</code></td>
          <td>{h(m.get('title', ''))}</td>
          <td>{sev_badge(m['severity'])}</td>
          <td>{status_badge(m.get('status', 'FAIL'))}</td>
          <td class="desc">{resolution}</td>
        </tr>"""

    # Secret rows
    secret_rows = ""
    for s in secrets:
        secret_rows += f"""
        <tr>
          <td>{h(s.get('target', ''))}</td>
          <td>{h(s.get('category', ''))}</td>
          <td>{h(s.get('title', ''))}</td>
          <td>{sev_badge(s.get('severity', 'HIGH'))}</td>
        </tr>"""

    # CIS controls table — DS-XXXX checks from Trivy Dockerfile scanner
    cis_rows = ""
    seen_cis = {}
    for m in misconfigs:
        mid = m.get("misconfig_id", "")
        if not (mid.startswith("DS-") or mid.startswith("CIS-")):
            continue
        if mid in seen_cis:
            continue
        seen_cis[mid] = True
        ctrl = CIS_DOCKER_CONTROLS.get(mid, {})
        level = ctrl.get("level", "L1")
        section = ctrl.get("section", "")
        cis_ref = ctrl.get("cis_id", "—")
        cis_rows += f"""
        <tr>
          <td><code>{h(mid)}</code></td>
          <td>{h(cis_ref)}</td>
          <td>{h(section)}</td>
          <td>{h(m.get('title') or ctrl.get('title', ''))}</td>
          <td>{h(level)}</td>
          <td>{status_badge(m.get('status', 'FAIL'))}</td>
          <td>{sev_badge(m.get('severity', 'LOW'))}</td>
        </tr>"""

    # Recommendations
    rec_items = ""
    for rec in recs:
        color = SEVERITY_COLORS.get(rec["priority"], "#757575")
        rec_items += f"""
        <li>
          <span class="badge" style="background:{color};min-width:80px">{h(rec['priority'])}</span>
          {h(rec['action'])}
        </li>"""

    # Bar chart data
    sev_labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
    vuln_bar_data = [vc.get(s, 0) for s in sev_labels]
    vuln_bar_colors = [SEVERITY_COLORS[s] for s in sev_labels]

    cis_section = ""
    if cis_rows:
        cis_section = f"""
        <section id="cis">
          <h2>CIS Docker Benchmark Compliance</h2>
          <p>Controls from <strong>CIS Docker Benchmark v1.6 — Section 4: Container Images and Build File</strong></p>
          <table>
            <thead>
              <tr>
                <th>Control ID</th><th>CIS Ref</th><th>Section</th><th>Description</th>
                <th>Level</th><th>Status</th><th>Severity</th>
              </tr>
            </thead>
            <tbody>{cis_rows}</tbody>
          </table>
        </section>"""

    secrets_section = ""
    if secrets:
        secrets_section = f"""
        <section id="secrets">
          <h2>⚠️ Exposed Secrets</h2>
          <div class="alert alert-critical">
            <strong>ACTION REQUIRED:</strong> {len(secrets)} secret(s) were found in this image.
            Rotate all exposed credentials immediately. Remove secrets from the image and use
            a secrets management solution (e.g., Vault, AWS Secrets Manager, Kubernetes Secrets).
          </div>
          <table>
            <thead>
              <tr><th>File/Layer</th><th>Category</th><th>Title</th><th>Severity</th></tr>
            </thead>
            <tbody>{secret_rows}</tbody>
          </table>
        </section>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Container Security Report — {h(image)}</title>
  <style>
    :root {{
      --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      --bg: #f8f9fa;
      --card: #ffffff;
      --border: #dee2e6;
      --text: #212529;
      --muted: #6c757d;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: var(--font); background: var(--bg); color: var(--text); line-height: 1.6; }}
    header {{
      background: #1a1a2e;
      color: white;
      padding: 2rem;
      border-bottom: 4px solid {risk_color};
    }}
    header h1 {{ font-size: 1.6rem; margin-bottom: 0.3rem; }}
    header .meta {{ color: #adb5bd; font-size: 0.85rem; }}
    nav {{
      background: #16213e;
      padding: 0.5rem 2rem;
      display: flex;
      gap: 1.5rem;
      flex-wrap: wrap;
    }}
    nav a {{ color: #90caf9; text-decoration: none; font-size: 0.9rem; }}
    nav a:hover {{ color: white; }}
    main {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
    section {{ background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; }}
    h2 {{ font-size: 1.3rem; margin-bottom: 1rem; padding-bottom: 0.5rem; border-bottom: 2px solid var(--border); }}
    h3 {{ font-size: 1.1rem; margin: 1rem 0 0.7rem; }}
    .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }}
    .stat-card {{
      background: var(--bg);
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 1rem;
      text-align: center;
    }}
    .stat-card .value {{ font-size: 2rem; font-weight: 700; }}
    .stat-card .label {{ font-size: 0.8rem; color: var(--muted); text-transform: uppercase; margin-top: 0.2rem; }}
    .risk-badge {{
      display: inline-block;
      background: {risk_color};
      color: white;
      padding: 0.4rem 1.2rem;
      border-radius: 4px;
      font-weight: 700;
      font-size: 1.1rem;
    }}
    .badge {{
      display: inline-block;
      color: white;
      padding: 0.2rem 0.6rem;
      border-radius: 3px;
      font-size: 0.75rem;
      font-weight: 600;
    }}
    .progress-bar {{ background: #e9ecef; border-radius: 4px; height: 20px; margin-top: 0.5rem; overflow: hidden; }}
    .progress-fill {{ height: 100%; border-radius: 4px; transition: width 0.3s; display: flex; align-items: center; padding: 0 0.5rem; color: white; font-size: 0.75rem; font-weight: 600; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 0.9rem; }}
    th {{ background: #f1f3f5; text-align: left; padding: 0.6rem 0.8rem; border: 1px solid var(--border); font-weight: 600; }}
    td {{ padding: 0.5rem 0.8rem; border: 1px solid var(--border); vertical-align: top; }}
    tr:hover {{ background: #f8f9fa; }}
    td.desc {{ max-width: 300px; font-size: 0.85rem; color: var(--muted); }}
    code {{ background: #e9ecef; padding: 0.1rem 0.4rem; border-radius: 3px; font-size: 0.85rem; }}
    a {{ color: #0d6efd; }}
    .alert-critical {{ background: #fff5f5; border: 1px solid #f5c2c7; border-left: 4px solid #d32f2f; padding: 1rem; border-radius: 4px; margin-bottom: 1rem; }}
    .sev-bar {{ display: flex; gap: 0.5rem; flex-wrap: wrap; margin: 0.8rem 0; }}
    .sev-item {{ display: flex; align-items: center; gap: 0.3rem; font-size: 0.85rem; }}
    .sev-dot {{ width: 12px; height: 12px; border-radius: 50%; }}
    ul.recs {{ list-style: none; padding: 0; }}
    ul.recs li {{ padding: 0.7rem 0; border-bottom: 1px solid var(--border); display: flex; gap: 0.8rem; align-items: flex-start; }}
    ul.recs li:last-child {{ border-bottom: none; }}
    .toc {{ background: #f1f3f5; border-radius: 6px; padding: 1rem 1.5rem; }}
    .toc ul {{ list-style: none; padding: 0; display: flex; flex-wrap: wrap; gap: 0.5rem 2rem; }}
    .toc li::before {{ content: "→ "; color: var(--muted); }}
    footer {{ text-align: center; color: var(--muted); font-size: 0.8rem; padding: 2rem; }}
  </style>
</head>
<body>
<header>
  <h1>🔒 Container Image Security Report</h1>
  <div class="meta">
    Image: <strong>{h(image)}</strong> &nbsp;|&nbsp;
    Scan Date: <strong>{ts[:19].replace('T', ' ')} UTC</strong> &nbsp;|&nbsp;
    Scanner: Trivy &nbsp;|&nbsp;
    Benchmark: CIS Docker Benchmark v1.6
  </div>
</header>

<nav>
  <a href="#summary">Executive Summary</a>
  <a href="#cis">CIS Compliance</a>
  <a href="#vulnerabilities">Vulnerabilities</a>
  <a href="#misconfigs">Misconfigurations</a>
  {"<a href='#secrets'>Secrets</a>" if secrets else ""}
  <a href="#recommendations">Recommendations</a>
  <a href="#appendix">Appendix</a>
</nav>

<main>

  <section id="summary">
    <h2>Executive Summary</h2>
    <div class="stats-grid">
      <div class="stat-card">
        <div class="value"><span class="risk-badge">{h(risk)}</span></div>
        <div class="label">Overall Risk Rating</div>
      </div>
      {"" if cis.get("total", 0) == 0 else f'''
      <div class="stat-card">
        <div class="value" style="color:{cis_bar_color}">{cis.get("score_pct", 0):.0f}%</div>
        <div class="label">CIS Compliance Score</div>
        <div class="progress-bar">
          <div class="progress-fill" style="width:{cis.get("score_pct", 0):.0f}%;background:{cis_bar_color}">
            {cis.get("passed",0)}/{cis.get("total",0)}
          </div>
        </div>
      </div>'''}
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['CRITICAL']}">{vc.get('CRITICAL', 0)}</div>
        <div class="label">Critical Vulnerabilities</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['HIGH']}">{vc.get('HIGH', 0)}</div>
        <div class="label">High Vulnerabilities</div>
      </div>
      <div class="stat-card">
        <div class="value" style="color:{SEVERITY_COLORS['MEDIUM']}">{vc.get('MEDIUM', 0)}</div>
        <div class="label">Medium Vulnerabilities</div>
      </div>
      <div class="stat-card">
        <div class="value">{sum(vc.values())}</div>
        <div class="label">Total Vulnerabilities</div>
      </div>
      <div class="stat-card">
        <div class="value">{len(fail_misconfigs)}</div>
        <div class="label">Failed CIS Checks</div>
      </div>
      {"" if not secrets else f'<div class="stat-card"><div class="value" style="color:#d32f2f">{len(secrets)}</div><div class="label">Exposed Secrets</div></div>'}
    </div>

    <h3>Severity Distribution</h3>
    <div class="sev-bar">
      {"".join(f'<div class="sev-item"><div class="sev-dot" style="background:{SEVERITY_COLORS[s]}"></div><strong>{vc.get(s,0)}</strong> {s}</div>' for s in ["CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"])}
    </div>
  </section>

  {cis_section}

  <section id="vulnerabilities">
    <h2>Vulnerability Findings ({len(vulns)} total)</h2>
    {"<p>No vulnerabilities found.</p>" if not vulns else f"""
    <table>
      <thead>
        <tr>
          <th>CVE ID</th><th>Package</th><th>Installed</th>
          <th>Fix Version</th><th>CVSS</th><th>Severity</th><th>Description</th>
        </tr>
      </thead>
      <tbody>{vuln_rows}</tbody>
    </table>
    {"" if len(vulns) <= 200 else f"<p style='color:var(--muted);margin-top:0.5rem'>Showing 200 of {len(vulns)} vulnerabilities. See raw JSON for full list.</p>"}
    """}
  </section>

  <section id="misconfigs">
    <h2>Misconfiguration Findings ({len(fail_misconfigs)} failed checks)</h2>
    {"<p>No misconfigurations found.</p>" if not fail_misconfigs else f"""
    <table>
      <thead>
        <tr><th>ID</th><th>Title</th><th>Severity</th><th>Status</th><th>Resolution</th></tr>
      </thead>
      <tbody>{misconfig_rows}</tbody>
    </table>"""}
  </section>

  {secrets_section}

  <section id="recommendations">
    <h2>Recommendations</h2>
    <ul class="recs">{rec_items}</ul>
  </section>

  <section id="appendix">
    <h2>Appendix</h2>
    <h3>Scan Methodology</h3>
    <p>This report was generated using <strong>Trivy</strong> by Aqua Security.
    The scanner checks vulnerabilities against multiple databases including NVD,
    OS vendor advisories (Ubuntu, Debian, Alpine, RHEL, etc.), and application package
    databases (npm, PyPI, Maven, etc.). Misconfigurations are checked against the
    CIS Docker Benchmark v1.6.</p>

    <h3 style="margin-top:1rem">About CIS Docker Benchmark</h3>
    <p>The CIS Docker Benchmark provides authoritative guidance for establishing a secure
    configuration posture for Docker. Level 1 controls offer basic security with minimal
    operational impact. Level 2 controls provide defense-in-depth but may impact usability.</p>
    <p>Reference: <a href="https://www.cisecurity.org/benchmark/docker" target="_blank">
    https://www.cisecurity.org/benchmark/docker</a></p>

    <h3 style="margin-top:1rem">Vulnerability Severity Scale</h3>
    <table style="max-width:600px">
      <thead><tr><th>Severity</th><th>CVSS Range</th><th>Recommended Action</th></tr></thead>
      <tbody>
        <tr><td>{sev_badge("CRITICAL")}</td><td>9.0–10.0</td><td>Fix immediately before deployment</td></tr>
        <tr><td>{sev_badge("HIGH")}</td><td>7.0–8.9</td><td>Fix within 7 days</td></tr>
        <tr><td>{sev_badge("MEDIUM")}</td><td>4.0–6.9</td><td>Fix within 30 days</td></tr>
        <tr><td>{sev_badge("LOW")}</td><td>0.1–3.9</td><td>Fix in next release cycle</td></tr>
      </tbody>
    </table>
  </section>

</main>
<footer>
  Generated by Container Image Security Scanner (Trivy) &nbsp;|&nbsp;
  CIS Docker Benchmark v1.6 &nbsp;|&nbsp;
  {ts[:10]}
</footer>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Generate security report from Trivy scan results"
    )
    parser.add_argument("--image", required=True, help="Image name that was scanned")
    parser.add_argument(
        "--raw-dir",
        help="Directory containing raw Trivy JSON files (vulnerabilities.json, misconfigurations.json)",
    )
    parser.add_argument(
        "--scan-json",
        help="Path to combined scan_results.json (output of scan_image.py)",
    )
    parser.add_argument(
        "--output-dir",
        default="./scan-results",
        help="Directory to write reports (default: ./scan-results)",
    )
    parser.add_argument(
        "--format",
        choices=["html", "markdown", "both"],
        default="both",
        help="Output format (default: both)",
    )
    args = parser.parse_args()

    if not args.raw_dir and not args.scan_json:
        parser.error("Either --raw-dir or --scan-json must be specified")

    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading scan data...")
    data = load_scan_data(
        raw_dir=args.raw_dir,
        scan_json=args.scan_json,
    )
    data["summary"]["image"] = args.image

    reports = []

    if args.format in ("html", "both"):
        html_path = output_dir / "security-report.html"
        print(f"Generating HTML report...")
        html = generate_html(data, args.image)
        html_path.write_text(html, encoding="utf-8")
        reports.append(str(html_path))
        print(f"  HTML report: {html_path}")

    if args.format in ("markdown", "both"):
        md_path = output_dir / "security-report.md"
        print(f"Generating Markdown report...")
        md = generate_markdown(data, args.image)
        md_path.write_text(md, encoding="utf-8")
        reports.append(str(md_path))
        print(f"  Markdown report: {md_path}")

    summary = data["summary"]
    risk = summary.get("risk_rating", "UNKNOWN")
    vc = summary.get("vulnerability_counts", {})
    mc = summary.get("misconfig_counts", {})
    cis = summary.get("cis_compliance", {})

    print(f"\n{'='*60}")
    print("REPORT GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"Image          : {args.image}")
    print(f"Risk Rating    : {risk}")
    if cis.get("total", 0) > 0:
        print(f"CIS Compliance : {cis.get('passed',0)}/{cis.get('total',0)} ({cis.get('score_pct',0):.1f}%)")
    print(f"Vulnerabilities: CRITICAL={vc.get('CRITICAL',0)} HIGH={vc.get('HIGH',0)} MEDIUM={vc.get('MEDIUM',0)} LOW={vc.get('LOW',0)}")
    print(f"Misconfigs     : CRITICAL={mc.get('CRITICAL',0)} HIGH={mc.get('HIGH',0)} MEDIUM={mc.get('MEDIUM',0)} LOW={mc.get('LOW',0)}")
    print(f"\nReports saved:")
    for r in reports:
        print(f"  {r}")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    main()
