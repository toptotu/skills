# Trivy JSON Output Schema Reference

This document describes the JSON output format produced by Trivy when scanning container images.
Use this reference when parsing or processing raw scan results.

## Top-Level Structure

```json
{
  "SchemaVersion": 2,
  "CreatedAt": "2024-01-15T10:30:00.000Z",
  "ArtifactName": "nginx:latest",
  "ArtifactType": "container_image",
  "Metadata": { ... },
  "Results": [ ... ]
}
```

## Metadata Object

```json
{
  "OS": {
    "Family": "debian",
    "Name": "12.4",
    "EOSL": false
  },
  "ImageID": "sha256:abc123...",
  "DiffIDs": ["sha256:layer1...", "sha256:layer2..."],
  "RepoTags": ["nginx:latest"],
  "RepoDigests": ["nginx@sha256:abc123..."],
  "ImageConfig": {
    "architecture": "amd64",
    "os": "linux",
    "config": {
      "Cmd": ["nginx", "-g", "daemon off;"],
      "Entrypoint": ["/docker-entrypoint.sh"],
      "Env": ["PATH=/usr/local/sbin:/usr/local/bin:..."],
      "ExposedPorts": {"80/tcp": {}},
      "User": ""
    }
  }
}
```

Key fields:
- `OS.Family`: OS family string (debian, ubuntu, alpine, centos, rhel, etc.)
- `OS.EOSL`: Whether the OS is End Of Service Life
- `ImageConfig.config.User`: Empty string = runs as root (CIS-DI-0001 fail)

## Results Array

Each entry in `Results` represents a scan target (OS layer, application layer, etc.):

```json
{
  "Target": "nginx:latest (debian 12.4)",
  "Class": "os-pkgs",
  "Type": "debian",
  "Vulnerabilities": [ ... ],
  "Misconfigurations": [ ... ],
  "Secrets": [ ... ]
}
```

**Target types:**
- `os-pkgs` / `debian`, `ubuntu`, `alpine`, etc. — OS package vulnerabilities
- `lang-pkgs` / `pip`, `npm`, `maven`, `cargo`, etc. — Application dependency vulnerabilities
- `config` / `dockerfile` — Dockerfile misconfigurations
- `secret` — Secret findings

## Vulnerability Object

```json
{
  "VulnerabilityID": "CVE-2023-44487",
  "PkgName": "libssl3",
  "InstalledVersion": "3.0.11-1~deb12u2",
  "FixedVersion": "3.0.13-1~deb12u1",
  "Status": "fixed",
  "Layer": {
    "Digest": "sha256:...",
    "DiffID": "sha256:..."
  },
  "SeveritySource": "nvd",
  "PrimaryURL": "https://avd.aquasec.com/nvd/cve-2023-44487",
  "Title": "HTTP/2 rapid reset attack",
  "Description": "The HTTP/2 protocol allows ...",
  "Severity": "HIGH",
  "CweIDs": ["CWE-400"],
  "CVSS": {
    "nvd": {
      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      "V3Score": 7.5
    },
    "redhat": {
      "V3Vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
      "V3Score": 7.5
    }
  },
  "References": [
    "https://github.com/advisories/GHSA-qppj-fm5r-hxr3",
    "https://www.cve.org/CVERecord?id=CVE-2023-44487"
  ],
  "PublishedDate": "2023-10-10T14:15:00Z",
  "LastModifiedDate": "2024-01-05T19:15:00Z"
}
```

Key fields:
- `Severity`: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN
- `FixedVersion`: Empty string if no fix available
- `CVSS`: Multiple scoring sources; prefer `V3Score` over `V2Score`
- `Status`: `fixed`, `affected`, `will_not_fix`, `fix_deferred`, `end_of_life`

## Misconfiguration Object

```json
{
  "Type": "Dockerfile Security Check",
  "ID": "CIS-DI-0001",
  "AVDID": "AVD-DS-0002",
  "Title": "Specify at least 1 USER command in Dockerfile with non-root user as argument",
  "Description": "Running containers with 'root' user can create security risks...",
  "Message": "Last USER command in Dockerfile should not be 'root'",
  "Namespace": "builtin.dockerfile.DS002",
  "Query": "data.builtin.dockerfile.DS002.deny",
  "Resolution": "Add USER <non-root-user> to Dockerfile",
  "Severity": "HIGH",
  "PrimaryURL": "https://avd.aquasec.com/misconfig/ds002",
  "References": [
    "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/",
    "https://www.cisecurity.org/benchmark/docker"
  ],
  "Status": "FAIL",
  "Layer": {},
  "CauseMetadata": {
    "Provider": "Dockerfile",
    "Service": "general",
    "StartLine": 1,
    "EndLine": 10,
    "Code": { "Lines": [] }
  }
}
```

Key fields:
- `ID`: Control ID (e.g., `CIS-DI-0001`)
- `AVDID`: Aqua Vulnerability Database ID
- `Status`: `PASS`, `FAIL`, or `EXCEPTION`
- `Severity`: CRITICAL, HIGH, MEDIUM, LOW

## Secret Object

```json
{
  "RuleID": "aws-access-key-id",
  "Category": "AWS",
  "Title": "AWS Access Key ID",
  "Severity": "CRITICAL",
  "StartLine": 5,
  "EndLine": 5,
  "Code": {
    "Lines": [
      {
        "Number": 5,
        "Content": "ENV AWS_ACCESS_KEY_ID=AKIA*****REDACTED*****",
        "IsCause": true,
        "Annotation": "",
        "Truncated": false,
        "FirstCause": true,
        "LastCause": true
      }
    ]
  },
  "Match": "AKIA****REDACTED****",
  "Layer": {
    "Digest": "sha256:...",
    "DiffID": "sha256:..."
  }
}
```

## Common Severity Mappings

### CVE Severity Sources
- `nvd` — National Vulnerability Database (NIST)
- `redhat` — Red Hat Security Advisory
- `ubuntu` — Ubuntu Security Notice
- `debian` — Debian Security Advisory
- `alpine` — Alpine Security Database
- `ghsa` — GitHub Security Advisory

Trivy uses the vendor severity where available, falling back to NVD CVSS scores.

## Parsing Tips

1. **Always check for null `Results`** — a clean image returns `"Results": null`
2. **Empty `Vulnerabilities`** in a target doesn't mean no vulns — check all targets
3. **`FixedVersion`** can be an empty string, a version string, or a range like `>= 3.0.1`
4. **`CVSS`** can have multiple sources — prefer the one with the highest score for risk assessment
5. **`Status: "PASS"`** in misconfigs means the check passed — only `"FAIL"` needs attention

## Trivy CLI Reference

```bash
# Vulnerability scan
trivy image --scanners vuln --format json nginx:latest

# Misconfiguration scan (includes CIS checks)
trivy image --scanners misconfig --format json nginx:latest

# Secret scan
trivy image --scanners secret --format json nginx:latest

# All scanners
trivy image --scanners vuln,misconfig,secret --format json nginx:latest

# Filter by severity
trivy image --severity CRITICAL,HIGH --format json nginx:latest

# Exit with failure if vulnerabilities found (CI/CD)
trivy image --exit-code 1 --severity CRITICAL nginx:latest

# Ignore unfixed vulnerabilities
trivy image --ignore-unfixed nginx:latest

# Update DB
trivy image --download-db-only --no-progress

# Scan from tar archive
docker save nginx:latest -o nginx.tar
trivy image --input nginx.tar --format json
```
