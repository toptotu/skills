---
name: container-image-scanner
description: Scan container images for security vulnerabilities and generate CIS benchmark-based security reports. Use this skill whenever a user wants to: scan a Docker/OCI container image for security issues, run CIS Docker Benchmark checks on a container image, generate a container security audit report, assess the security posture of an image, analyze a Dockerfile or image for misconfigurations, check CVE vulnerabilities in a container, perform security compliance checks against CIS standards, or produce a penetration testing / security review of any container image. Trigger even if the user just says "scan my image", "check my container security", or "is this image safe?".
---

# Container Image Security Scanner

This skill scans container images against the **CIS Docker Benchmark** and known CVE databases, then produces a structured security report in HTML and Markdown formats.

## What This Skill Does

1. **Installs Trivy** (if not present) — the leading open-source container security scanner
2. **Scans the image** for:
   - OS and application CVE vulnerabilities
   - CIS Docker Benchmark misconfigurations (Section 4: Container Images)
   - Exposed secrets and credentials
3. **Generates a security report** containing:
   - Executive Summary with overall risk rating
   - CIS Benchmark compliance scorecard
   - Vulnerability findings ranked by severity (Critical → High → Medium → Low → Info)
   - Misconfiguration findings with CIS control references
   - Actionable remediation recommendations

## Workflow

### Step 1 – Gather Requirements

Ask the user for:
- **Image name/tag** (e.g., `nginx:latest`, `myapp:1.0`, or a full registry path)
- **Output format preference**: HTML report (default), Markdown, or both
- **Output location**: where to save the report (default: current directory)
- **Scan depth**: Standard (vulnerabilities + misconfigs) or Full (+ secrets scanning)

If the user has already specified the image in their request, skip asking and proceed directly.

### Step 2 – Set Up Trivy

Run the setup script to ensure Trivy is installed and its vulnerability database is up to date:

```bash
python scripts/setup_trivy.py
```

This script will:
- Check if Trivy exists at `~/.local/bin/trivy` or in `$PATH`
- Download and install the latest release if missing
- Update the vulnerability database

### Step 3 – Run the Scan

Execute the main scanning script:

```bash
# Scan a built container image (CVE + image config checks)
python scripts/scan_image.py \
  --image <IMAGE_NAME> \
  --output-dir <OUTPUT_DIR> \
  [--scan-secrets]

# Scan a Dockerfile for CIS benchmark misconfigurations
python scripts/scan_image.py \
  --dockerfile <PATH_TO_DOCKERFILE_OR_DIRECTORY> \
  --output-dir <OUTPUT_DIR>

# Scan both image AND Dockerfile for maximum coverage
python scripts/scan_image.py \
  --image <IMAGE_NAME> \
  --dockerfile <PATH_TO_DOCKERFILE> \
  --output-dir <OUTPUT_DIR> \
  --scan-secrets
```

The script runs Trivy in multiple modes and merges results:
1. **Vulnerability scan** (`trivy image --scanners vuln`) — requires `--image`
2. **Image config scan** (`trivy image --scanners misconfig`) — checks image metadata (user, etc.)
3. **Dockerfile scan** (`trivy config`) — checks Dockerfile instructions against CIS benchmark; requires `--dockerfile`
4. **Secret scan** (`trivy image --scanners secret`) — only if `--scan-secrets` flag is set; requires `--image`

Raw JSON results are saved to `<output-dir>/raw/`.

### Step 4 – Generate the Report

```bash
python scripts/generate_report.py \
  --raw-dir <OUTPUT_DIR>/raw \
  --output-dir <OUTPUT_DIR> \
  --image <IMAGE_NAME> \
  [--format html|markdown|both]
```

The report will be saved as:
- `<output-dir>/security-report.html` (interactive HTML with charts)
- `<output-dir>/security-report.md` (Markdown summary)

### Step 5 – Present Results

After generation:
1. Show the user the **Executive Summary** inline (severity counts, CIS compliance %)
2. Tell the user the path to the full HTML report
3. Highlight the **top 3 most critical findings** with remediation advice
4. If any **Critical** vulnerabilities are found, clearly flag them at the top of your response

## Report Structure

The generated report follows this structure:

```
# Container Image Security Report
## Metadata (image, scan date, tool versions)
## Executive Summary
  - Overall Risk Rating: CRITICAL / HIGH / MEDIUM / LOW
  - CIS Benchmark Compliance: X/Y checks passed (Z%)
  - Vulnerability counts by severity
## CIS Docker Benchmark Compliance (Section 4)
  - Per-control table: Control ID | Description | Status | Evidence
## Vulnerability Findings
  - Summary chart by severity
  - Per-finding: CVE ID | Package | Version | Fix Version | CVSS | Description
## Misconfiguration Findings
  - Per-finding: CIS ID | Title | Severity | Description | Remediation
## Exposed Secrets (if scanned)
## Recommendations
  - Prioritized action list
## Appendix
  - Scan methodology, tool versions, raw finding counts
```

## CIS Docker Benchmark Reference

The CIS Docker Benchmark controls most relevant to image scanning are in **Section 4 (Container Images and Build File)**. Read `references/cis_docker_benchmark.md` for the full control list with descriptions, rationale, and remediation steps.

Key controls checked (Trivy DS-XXXX → CIS Docker Benchmark mapping):
| Trivy ID | CIS Section | Description | Level |
|----------|-------------|-------------|-------|
| DS-0002  | CIS 4.1 | Image user should not be 'root' | L1 |
| DS-0004  | CIS 5.7 | Port 22 (SSH) should not be exposed | L1 |
| DS-0005  | CIS 4.9 | Use COPY instead of ADD | L1 |
| DS-0017  | CIS 4.7 | Do not use update instructions alone | L1 |
| DS-0026  | CIS 4.6 | Add HEALTHCHECK to images | L1 |
| DS-0029  | CIS 4.3 | Remove unnecessary packages | L1 |
| DS-0031  | CIS 4.10 | Do not store secrets in Dockerfiles/ENV | L1 |
| DS-0032  | CIS 4.2  | Use specific version tags (not `latest`) | L1 |

Trivy also maps CVEs and misconfigurations to additional CIS benchmarks (Ubuntu CIS, Alpine CIS, RHEL CIS, etc.) based on the image's OS.

## Severity Ratings

| Severity | CVSS Range | Action |
|----------|-----------|--------|
| CRITICAL | 9.0–10.0 | Fix immediately before deployment |
| HIGH | 7.0–8.9 | Fix within 7 days |
| MEDIUM | 4.0–6.9 | Fix within 30 days |
| LOW | 0.1–3.9 | Fix in next release cycle |
| INFO / UNKNOWN | — | Review and document |

## Overall Risk Rating Formula

The overall image risk rating is determined by the highest severity present:
- Any CRITICAL finding → Overall: **CRITICAL**
- Any HIGH finding (no CRITICAL) → Overall: **HIGH**
- Any MEDIUM finding (no CRITICAL/HIGH) → Overall: **MEDIUM**
- Only LOW/INFO findings → Overall: **LOW**
- No findings → Overall: **PASS**

CIS compliance score = (passed controls / total applicable controls) × 100

## Example Usage

**User:** "Scan the nginx:latest image and give me a security report"

**You:** Run Steps 2–5 above with `--image nginx:latest`. Generate both HTML and Markdown reports. Present the executive summary inline.

**User:** "Check if my Docker image python:3.9-slim has any critical vulnerabilities"

**You:** Run a vulnerability scan with `--image python:3.9-slim`. If CRITICAL findings exist, list them clearly with CVE IDs, affected packages, and available fix versions.

## Error Handling

- **Image not found**: Tell the user the image couldn't be pulled and ask them to verify the name/tag and registry credentials
- **Trivy install fails**: Check `/tmp/trivy-install.log` for details; offer to use a pre-downloaded binary
- **Scan times out**: For large images, add `--timeout 10m` to the trivy commands in `scan_image.py`
- **Network issues**: Trivy can scan cached images offline; check if the image is already pulled with `docker images`

## Reference Files

- `references/cis_docker_benchmark.md` — Full CIS Docker Benchmark Section 4 controls with remediation guidance
- `references/trivy_output_schema.md` — Trivy JSON output format for understanding raw results
