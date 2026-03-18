#!/usr/bin/env python3
"""
Container image security scanner using Trivy.
Scans for CVE vulnerabilities, CIS Docker Benchmark misconfigurations,
and optionally exposed secrets.

Usage:
    python scripts/scan_image.py --image nginx:latest --output-dir ./report
    python scripts/scan_image.py --image myapp:1.0 --output-dir ./report --scan-secrets
    python scripts/scan_image.py --help
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def find_trivy() -> str:
    """Locate trivy binary or raise."""
    path = shutil.which("trivy")
    if path:
        return path
    local = os.path.join(os.path.expanduser("~/.local/bin"), "trivy")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    raise RuntimeError(
        "trivy not found. Run `python scripts/setup_trivy.py` first."
    )


def run_trivy(trivy_bin: str, args: list[str], label: str) -> dict:
    """Run trivy with given args, return parsed JSON output."""
    cmd = [trivy_bin] + args + ["--format", "json", "--quiet", "--no-progress"]
    print(f"  Running {label} scan...")
    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode not in (0, 1):
        # returncode 1 can mean findings were found (not an error)
        print(f"  Warning: trivy exited with code {result.returncode}")
        if result.stderr:
            print(f"  stderr: {result.stderr[:500]}")

    if not result.stdout.strip():
        print(f"  Warning: empty output for {label} scan")
        return {}

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as e:
        print(f"  Warning: failed to parse JSON for {label}: {e}")
        return {}


def scan_vulnerabilities(trivy_bin: str, image: str, timeout: str) -> dict:
    return run_trivy(
        trivy_bin,
        [
            "image",
            "--scanners", "vuln",
            "--timeout", timeout,
            "--no-progress",
            image,
        ],
        "vulnerability",
    )


def scan_misconfigurations(trivy_bin: str, image: str, timeout: str) -> dict:
    return run_trivy(
        trivy_bin,
        [
            "image",
            "--scanners", "misconfig",
            "--timeout", timeout,
            "--no-progress",
            image,
        ],
        "misconfiguration",
    )


def scan_dockerfile(trivy_bin: str, dockerfile_path: str) -> dict:
    """Scan a Dockerfile for CIS benchmark misconfigurations using trivy config.
    
    dockerfile_path can be either a path to a Dockerfile file or a directory containing one.
    trivy config requires a directory argument.
    """
    import tempfile
    import shutil

    # trivy config works on a directory, not a file
    if os.path.isfile(dockerfile_path):
        # Create a temp directory with just the Dockerfile
        tmpdir = tempfile.mkdtemp(prefix="trivy-dockerfile-")
        try:
            dest = os.path.join(tmpdir, "Dockerfile")
            shutil.copy2(dockerfile_path, dest)
            return _run_trivy_config(trivy_bin, tmpdir)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
    elif os.path.isdir(dockerfile_path):
        return _run_trivy_config(trivy_bin, dockerfile_path)
    else:
        print(f"  Warning: Dockerfile path does not exist: {dockerfile_path}")
        return {}


def _run_trivy_config(trivy_bin: str, directory: str) -> dict:
    """Run trivy config on a directory, return parsed JSON."""
    cmd = [
        trivy_bin, "config",
        "--format", "json",
        "--quiet",
        directory,
    ]
    print(f"  Running Dockerfile misconfiguration scan...")
    result = subprocess.run(cmd, capture_output=True, text=True)
    if not result.stdout.strip():
        print(f"  Warning: empty output from Dockerfile scan")
        if result.stderr:
            print(f"  stderr: {result.stderr[:300]}")
        return {}
    # Filter out any non-JSON lines (trivy may mix logs)
    lines = result.stdout.strip().splitlines()
    json_start = next((i for i, l in enumerate(lines) if l.strip().startswith("{")), None)
    if json_start is None:
        print(f"  Warning: no JSON found in Dockerfile scan output")
        return {}
    json_text = "\n".join(lines[json_start:])
    try:
        return json.loads(json_text)
    except json.JSONDecodeError as e:
        print(f"  Warning: failed to parse Dockerfile scan JSON: {e}")
        return {}


def scan_secrets(trivy_bin: str, image: str, timeout: str) -> dict:
    return run_trivy(
        trivy_bin,
        [
            "image",
            "--scanners", "secret",
            "--timeout", timeout,
            "--no-progress",
            image,
        ],
        "secret",
    )


def extract_image_metadata(scan_data: dict) -> dict:
    """Pull OS, arch, and image digest info from scan results."""
    metadata = {}
    if "Metadata" in scan_data:
        m = scan_data["Metadata"]
        metadata["os"] = m.get("OS", {})
        metadata["image_id"] = m.get("ImageID", "")
        metadata["diff_ids"] = m.get("DiffIDs", [])
        metadata["repo_tags"] = m.get("RepoTags", [])
        metadata["repo_digests"] = m.get("RepoDigests", [])
    return metadata


def count_severities(results: list[dict], finding_key: str) -> dict[str, int]:
    """Count findings by severity across all result targets."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0}
    for target in results:
        for finding in target.get(finding_key, []) or []:
            sev = (finding.get("Severity") or "UNKNOWN").upper()
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def determine_risk_rating(vuln_counts: dict, misconfig_counts: dict) -> str:
    """Return overall risk rating based on highest severity found."""
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if vuln_counts.get(severity, 0) > 0 or misconfig_counts.get(severity, 0) > 0:
            return severity
    return "PASS"


def build_summary(
    image: str,
    vuln_data: dict,
    misconfig_data: dict,
    secret_data: dict,
) -> dict:
    """Build a structured summary from all scan results."""
    vuln_results = vuln_data.get("Results", []) or []
    misconfig_results = misconfig_data.get("Results", []) or []
    secret_results = secret_data.get("Results", []) if secret_data else []

    vuln_counts = count_severities(vuln_results, "Vulnerabilities")
    misconfig_counts = count_severities(misconfig_results, "Misconfigurations")

    secret_count = sum(
        len(r.get("Secrets", []) or []) for r in (secret_results or [])
    )

    risk_rating = determine_risk_rating(vuln_counts, misconfig_counts)

    # CIS compliance: count misconfig pass/fail
    total_checks = 0
    passed_checks = 0
    for target in misconfig_results:
        for m in target.get("Misconfigurations", []) or []:
            total_checks += 1
            if m.get("Status") == "PASS":
                passed_checks += 1

    cis_score = round(passed_checks / total_checks * 100, 1) if total_checks > 0 else None

    return {
        "image": image,
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "risk_rating": risk_rating,
        "cis_compliance": {
            "passed": passed_checks,
            "total": total_checks,
            "score_pct": cis_score,
        },
        "vulnerability_counts": vuln_counts,
        "misconfig_counts": misconfig_counts,
        "secret_count": secret_count,
        "total_vulnerabilities": sum(vuln_counts.values()),
        "total_misconfigs": sum(misconfig_counts.values()),
        "image_metadata": extract_image_metadata(vuln_data),
    }


def collect_all_vulnerabilities(results: list[dict]) -> list[dict]:
    """Flatten all vulnerability findings from all targets."""
    findings = []
    for target in results:
        target_name = target.get("Target", "")
        target_type = target.get("Type", "")
        for v in target.get("Vulnerabilities", []) or []:
            findings.append(
                {
                    "target": target_name,
                    "target_type": target_type,
                    "vuln_id": v.get("VulnerabilityID", ""),
                    "pkg_name": v.get("PkgName", ""),
                    "installed_version": v.get("InstalledVersion", ""),
                    "fixed_version": v.get("FixedVersion", ""),
                    "severity": v.get("Severity", "UNKNOWN"),
                    "cvss_score": _get_cvss(v),
                    "title": v.get("Title", ""),
                    "description": v.get("Description", "")[:500] if v.get("Description") else "",
                    "references": v.get("References", [])[:3],
                    "published_date": v.get("PublishedDate", ""),
                    "last_modified_date": v.get("LastModifiedDate", ""),
                    "cwe_ids": v.get("CweIDs", []),
                    "primary_url": v.get("PrimaryURL", ""),
                }
            )
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda x: (sev_order.get(x["severity"].upper(), 5), -float(x["cvss_score"] or 0)))
    return findings


def _get_cvss(vuln: dict) -> float | None:
    """Extract best CVSS score from a vulnerability entry."""
    cvss = vuln.get("CVSS", {})
    scores = []
    for source_data in cvss.values():
        for key in ("V3Score", "V2Score"):
            val = source_data.get(key)
            if val is not None:
                try:
                    scores.append(float(val))
                except (ValueError, TypeError):
                    pass
    return round(max(scores), 1) if scores else None


def collect_all_misconfigurations(results: list[dict]) -> list[dict]:
    """Flatten all misconfiguration findings from all targets."""
    findings = []
    for target in results:
        target_name = target.get("Target", "")
        for m in target.get("Misconfigurations", []) or []:
            findings.append(
                {
                    "target": target_name,
                    "misconfig_id": m.get("ID", ""),
                    "avd_id": m.get("AVDID", ""),
                    "type": m.get("Type", ""),
                    "title": m.get("Title", ""),
                    "description": m.get("Description", ""),
                    "message": m.get("Message", ""),
                    "severity": m.get("Severity", "UNKNOWN"),
                    "status": m.get("Status", "FAIL"),
                    "resolution": m.get("Resolution", ""),
                    "references": m.get("References", [])[:3],
                    "cis_controls": _extract_cis_controls(m),
                }
            )
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(
        key=lambda x: (
            0 if x["status"] == "FAIL" else 1,
            sev_order.get(x["severity"].upper(), 5),
        )
    )
    return findings


def _extract_cis_controls(misconfig: dict) -> list[str]:
    """Extract CIS control references from a misconfiguration entry."""
    controls = []
    for ref in misconfig.get("References", []):
        if "cisecurity.org" in ref or "cis-" in ref.lower() or "avd.aquasec" in ref:
            controls.append(ref)
    mid = misconfig.get("ID", "")
    if mid.startswith("CIS-") or mid.startswith("DS-"):
        controls.insert(0, mid)
    avd = misconfig.get("AVDID", "")
    if avd:
        controls.append(f"AVD: {avd}")
    return controls


def collect_all_secrets(results: list[dict]) -> list[dict]:
    """Flatten all secret findings from all targets."""
    findings = []
    for target in (results or []):
        target_name = target.get("Target", "")
        for s in target.get("Secrets", []) or []:
            findings.append(
                {
                    "target": target_name,
                    "rule_id": s.get("RuleID", ""),
                    "category": s.get("Category", ""),
                    "title": s.get("Title", ""),
                    "severity": s.get("Severity", "HIGH"),
                    "match": s.get("Match", "")[:100],
                }
            )
    return findings


def save_json(data: dict, path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)


def main():
    parser = argparse.ArgumentParser(
        description="Scan a container image for security issues using Trivy"
    )
    parser.add_argument("--image", required=False, help="Container image to scan (e.g. nginx:latest)")
    parser.add_argument("--dockerfile", help="Path to a Dockerfile or directory containing one (for CIS Dockerfile checks)")
    parser.add_argument(
        "--output-dir",
        default="./scan-results",
        help="Directory to save scan results (default: ./scan-results)",
    )
    parser.add_argument(
        "--scan-secrets",
        action="store_true",
        help="Also scan for exposed secrets/credentials",
    )
    parser.add_argument(
        "--timeout",
        default="5m",
        help="Scan timeout (default: 5m)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Skip DB update (use cached DB)",
    )
    args = parser.parse_args()

    if not args.image and not args.dockerfile:
        print("ERROR: At least one of --image or --dockerfile must be specified", file=sys.stderr)
        sys.exit(1)

    target_label = args.image or args.dockerfile

    output_dir = Path(args.output_dir)
    raw_dir = output_dir / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    try:
        trivy_bin = find_trivy()
    except RuntimeError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"\n{'='*60}")
    print(f"Container Image Security Scan")
    print(f"{'='*60}")
    if args.image:
        print(f"Image:      {args.image}")
    if args.dockerfile:
        print(f"Dockerfile: {args.dockerfile}")
    print(f"Scanner:    Trivy ({trivy_bin})")
    print(f"Output:     {output_dir}")
    print(f"Timestamp:  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'='*60}\n")

    vuln_data = {}
    misconfig_data = {}

    if args.image:
        print("[1/4] Scanning for CVE vulnerabilities...")
        vuln_data = scan_vulnerabilities(trivy_bin, args.image, args.timeout)
        save_json(vuln_data, str(raw_dir / "vulnerabilities.json"))

        print("[2/4] Scanning for CIS benchmark misconfigurations (image config)...")
        misconfig_data = scan_misconfigurations(trivy_bin, args.image, args.timeout)
    else:
        print("[1/4] CVE vulnerability scan skipped (no --image provided)")
        print("[2/4] Scanning for CIS benchmark misconfigurations (image config)...")

    if args.dockerfile:
        print(f"[2b] Scanning Dockerfile for CIS benchmark checks: {args.dockerfile}")
        dockerfile_data = scan_dockerfile(trivy_bin, args.dockerfile)
        # Merge Dockerfile misconfig results into misconfig_data
        if dockerfile_data.get("Results"):
            existing = misconfig_data.get("Results") or []
            misconfig_data["Results"] = existing + dockerfile_data.get("Results", [])

    if misconfig_data:
        save_json(misconfig_data, str(raw_dir / "misconfigurations.json"))

    secret_data = {}
    if args.scan_secrets and args.image:
        print("[3/4] Scanning for exposed secrets...")
        secret_data = scan_secrets(trivy_bin, args.image, args.timeout)
        save_json(secret_data, str(raw_dir / "secrets.json"))
    elif args.scan_secrets and not args.image:
        print("[3/4] Secret scanning requires --image (skipped for Dockerfile-only mode)")
    else:
        print("[3/4] Secret scanning skipped (use --scan-secrets to enable)")

    print("[4/4] Building summary...")
    summary = build_summary(target_label, vuln_data, misconfig_data, secret_data)

    all_vulns = collect_all_vulnerabilities(vuln_data.get("Results", []) or [])
    all_misconfigs = collect_all_misconfigurations(misconfig_data.get("Results", []) or [])
    all_secrets = collect_all_secrets(secret_data.get("Results", []) if secret_data else [])

    combined = {
        "summary": summary,
        "vulnerabilities": all_vulns,
        "misconfigurations": all_misconfigs,
        "secrets": all_secrets,
    }

    combined_path = output_dir / "scan_results.json"
    save_json(combined, str(combined_path))

    # Print quick summary
    print(f"\n{'='*60}")
    print("SCAN COMPLETE — Quick Summary")
    print(f"{'='*60}")
    print(f"Overall Risk Rating : {summary['risk_rating']}")
    if summary["cis_compliance"]["total"] > 0:
        print(
            f"CIS Compliance      : {summary['cis_compliance']['passed']}/{summary['cis_compliance']['total']} "
            f"({summary['cis_compliance']['score_pct']}%)"
        )
    vc = summary["vulnerability_counts"]
    print(
        f"Vulnerabilities     : "
        f"CRITICAL={vc['CRITICAL']}  HIGH={vc['HIGH']}  "
        f"MEDIUM={vc['MEDIUM']}  LOW={vc['LOW']}"
    )
    mc = summary["misconfig_counts"]
    print(
        f"Misconfigurations   : "
        f"CRITICAL={mc['CRITICAL']}  HIGH={mc['HIGH']}  "
        f"MEDIUM={mc['MEDIUM']}  LOW={mc['LOW']}"
    )
    if args.scan_secrets:
        print(f"Exposed Secrets     : {summary['secret_count']}")
    print(f"\nRaw results saved to: {raw_dir}")
    print(f"Combined JSON saved to: {combined_path}")
    print(f"\nNext step: python scripts/generate_report.py --raw-dir {raw_dir} --output-dir {output_dir} --image '{target_label}'")
    print(f"{'='*60}\n")

    return str(combined_path)


if __name__ == "__main__":
    main()
