# CIS Docker Benchmark v1.6 — Container Images Reference

This document covers **Section 4: Container Images and Build File** of the CIS Docker Benchmark,
which is the primary focus for image-level security scanning.

**Benchmark:** CIS Docker Benchmark v1.6  
**Published:** Center for Internet Security (CIS)  
**Source:** https://www.cisecurity.org/benchmark/docker

---

## Table of Contents

- [Section 4 Overview](#section-4-overview)
- [4.1 — Create a user for the container (CIS-DI-0001)](#41--create-a-user-for-the-container)
- [4.2 — Use only trusted base images (CIS-DI-0002)](#42--use-only-trusted-base-images)
- [4.3 — Do not install unnecessary packages (CIS-DI-0003)](#43--do-not-install-unnecessary-packages)
- [4.4 — Scan and rebuild images to include security patches (CIS-DI-0004)](#44--scan-and-rebuild-images)
- [4.5 — Enable Content Trust for Docker (CIS-DI-0005)](#45--enable-content-trust)
- [4.6 — Add HEALTHCHECK to the container image (CIS-DI-0006)](#46--add-healthcheck)
- [4.7 — Do not use update instructions alone (CIS-DI-0007)](#47--do-not-use-update-alone)
- [4.8 — Remove setuid and setgid permissions (CIS-DI-0008)](#48--remove-setuid-and-setgid)
- [4.9 — Use COPY instead of ADD (CIS-DI-0009)](#49--use-copy-instead-of-add)
- [4.10 — Do not store secrets in Dockerfiles (CIS-DI-0010)](#410--do-not-store-secrets)
- [4.11 — Only install verified packages (CIS-DI-0011)](#411--only-install-verified-packages)
- [Additional Image Checks](#additional-image-checks)
- [Severity Rating Guidelines](#severity-rating-guidelines)
- [CI/CD Integration](#cicd-integration)

---

## Section 4 Overview

Section 4 of the CIS Docker Benchmark focuses on the security of container images and Dockerfiles.
Container images are the foundation of all containers — a vulnerable or misconfigured image
propagates security risks to every container spawned from it.

**Control Levels:**
- **Level 1 (L1):** Basic security configurations that have minimal operational impact.
  Recommended for all environments.
- **Level 2 (L2):** Defense-in-depth configurations that may have some operational impact.
  Recommended for high-security environments.

---

## 4.1 — Create a user for the container

**Control ID:** CIS-DI-0001  
**CIS Section:** 4.1  
**Level:** L1  
**Trivy Check:** `DS002`

### Description

Containers should not run as the `root` user. Running as root means that if a process escapes
the container, it has root-level access on the host system.

### Audit

Check if the image defines a non-root USER:

```dockerfile
# FAIL — no USER defined, defaults to root
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y nginx

# PASS — explicit non-root user
FROM ubuntu:22.04
RUN groupadd -r appgroup && useradd -r -g appgroup appuser
USER appuser
```

Trivy check: The image's configuration should have `User` set to a non-root, non-empty value.

### Rationale

Running containers as root bypasses Linux user permission controls and gives attackers
full access to the host if they escape container isolation.

### Remediation

Add to your Dockerfile:

```dockerfile
RUN groupadd -r appuser && useradd --no-log-init -r -g appuser appuser
USER appuser
```

For images where an application needs elevated startup privileges, use `gosu` or `su-exec`
to drop privileges at runtime:

```dockerfile
ENTRYPOINT ["gosu", "appuser", "myapp"]
```

---

## 4.2 — Use only trusted base images

**Control ID:** CIS-DI-0002  
**CIS Section:** 4.2  
**Level:** L1

### Description

Use only images from trusted sources and official repositories. Unverified images may contain
malware, backdoors, or vulnerabilities.

### Rationale

Supply chain attacks often target base images. Using official images from Docker Hub's
"Official Images" program or verified publisher images reduces this risk.

### Remediation

- Prefer images from `docker.io/library/` (official Docker Hub images)
- Use image digests (`@sha256:...`) instead of mutable tags in production
- Enable Docker Content Trust: `export DOCKER_CONTENT_TRUST=1`
- Use a private registry with image scanning integrated

```dockerfile
# Using a digest for reproducibility
FROM ubuntu@sha256:a4bbf4b9e8e1e5a5f6d6d7e3b1a2c3d4e5f6a7b8...
```

---

## 4.3 — Do not install unnecessary packages

**Control ID:** CIS-DI-0003  
**CIS Section:** 4.3  
**Level:** L1

### Description

The image should contain only the packages necessary to run the application.
Unnecessary packages increase the attack surface and number of potential CVEs.

### Rationale

Every installed package is a potential vulnerability. Minimal images have fewer
CVEs and a smaller blast radius if compromised.

### Remediation

Use multi-stage builds to separate build tools from runtime images:

```dockerfile
# Build stage
FROM golang:1.21 AS builder
WORKDIR /app
COPY . .
RUN go build -o /app/myapp

# Runtime stage — minimal image
FROM gcr.io/distroless/static-debian12
COPY --from=builder /app/myapp /myapp
ENTRYPOINT ["/myapp"]
```

Alternatively, use Alpine or slim variants:

```dockerfile
FROM python:3.12-slim  # instead of python:3.12
```

After installing packages, clean up cache:

```dockerfile
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev \
 && rm -rf /var/lib/apt/lists/*
```

---

## 4.4 — Scan and rebuild images

**Control ID:** CIS-DI-0004  
**CIS Section:** 4.4  
**Level:** L1

### Description

Images should be regularly scanned for vulnerabilities and rebuilt when critical
patches are released.

### Rationale

Base images and application dependencies receive security patches over time. Without
regular rebuilds, containers continue running with known vulnerabilities.

### Remediation

- Integrate vulnerability scanning in CI/CD pipelines (this skill)
- Set up automated rebuilds triggered by base image updates
- Use tools like Dependabot or Renovate to update dependency versions

```bash
# Example: Fail CI/CD if CRITICAL vulnerabilities exist
trivy image --exit-code 1 --severity CRITICAL myapp:latest
```

---

## 4.5 — Enable Content Trust

**Control ID:** CIS-DI-0005  
**CIS Section:** 4.5  
**Level:** L2

### Description

Docker Content Trust (DCT) provides the ability to use digital signatures for data
sent to and received from remote Docker registries.

### Rationale

DCT ensures that pulled images are signed by trusted publishers, preventing
man-in-the-middle attacks and image tampering.

### Remediation

```bash
export DOCKER_CONTENT_TRUST=1
```

Or sign images using Docker Notary or Cosign (Sigstore):

```bash
# Sign with Cosign
cosign sign --key cosign.key myregistry/myapp:1.0
# Verify
cosign verify --key cosign.pub myregistry/myapp:1.0
```

---

## 4.6 — Add HEALTHCHECK

**Control ID:** CIS-DI-0006  
**CIS Section:** 4.6  
**Level:** L1  
**Trivy Check:** `DS026`

### Description

The HEALTHCHECK instruction tells Docker how to test that the container is still working.
Without it, Docker has no way to distinguish a healthy container from a broken one.

### Rationale

Health checks enable automatic detection and replacement of unhealthy containers,
improving resilience and security posture monitoring.

### Remediation

Add a HEALTHCHECK to your Dockerfile:

```dockerfile
# HTTP health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# TCP health check (using nc)
HEALTHCHECK --interval=30s --timeout=3s \
  CMD nc -z localhost 5432 || exit 1

# Application-level check
HEALTHCHECK --interval=60s --timeout=10s \
  CMD /app/healthcheck.sh || exit 1
```

---

## 4.7 — Do not use update alone

**Control ID:** CIS-DI-0007  
**CIS Section:** 4.7  
**Level:** L1  
**Trivy Check:** `DS005`

### Description

Using `RUN apt-get update` or `RUN yum update` alone in a layer (without installing
specific packages) creates cached layers that can serve stale package metadata on rebuild.

### Rationale

Cached update layers lead to Docker using outdated package lists, potentially installing
vulnerable package versions that have since been patched.

### Remediation

Always combine update with install in a single RUN instruction:

```dockerfile
# FAIL — update in separate layer
RUN apt-get update
RUN apt-get install -y nginx

# PASS — combined in single layer
RUN apt-get update && apt-get install -y --no-install-recommends nginx \
 && rm -rf /var/lib/apt/lists/*
```

---

## 4.8 — Remove setuid and setgid permissions

**Control ID:** CIS-DI-0008  
**CIS Section:** 4.8  
**Level:** L2

### Description

`setuid` (SUID) and `setgid` (SGID) bits allow executables to run with elevated privileges.
These should be removed from container images unless explicitly required.

### Rationale

SUID/SGID binaries can be abused to escalate privileges within a container.
Removing them reduces the attack surface significantly.

### Remediation

Add to your Dockerfile to strip SUID/SGID bits:

```dockerfile
RUN find / -xdev \( -perm -4000 -o -perm -2000 \) -type f -exec chmod a-s {} \; 2>/dev/null || true
```

Or use a distroless image which does not contain these binaries.

To audit existing SUID/SGID files:

```bash
docker run --rm <image> find / -xdev \( -perm -4000 -o -perm -2000 \) -type f
```

---

## 4.9 — Use COPY instead of ADD

**Control ID:** CIS-DI-0009  
**CIS Section:** 4.9  
**Level:** L1  
**Trivy Check:** `DS005`

### Description

The `ADD` instruction can auto-extract archives and fetch from URLs, making behavior
less predictable. `COPY` only copies local files and is more explicit.

### Rationale

`ADD` from URLs can download arbitrary content without verification, creating a
supply chain risk. `COPY` is always explicit and auditable.

### Remediation

Replace `ADD` with `COPY` for local files:

```dockerfile
# FAIL
ADD ./app.tar.gz /app/

# PASS
COPY ./app /app/

# If you need to extract archives, be explicit:
COPY ./app.tar.gz /tmp/
RUN tar -xzf /tmp/app.tar.gz -C /app && rm /tmp/app.tar.gz
```

---

## 4.10 — Do not store secrets in Dockerfiles

**Control ID:** CIS-DI-0010  
**CIS Section:** 4.10  
**Level:** L1

### Description

Credentials, passwords, API keys, and other secrets must not be embedded in
Dockerfile instructions or committed to source control.

### Rationale

Every layer in a Docker image is stored and can be inspected with `docker history`.
Secrets added via ENV or ARG persist in the image and are trivially extractable.

### What Trivy Detects

Trivy's secrets scanner looks for:
- AWS access keys / secret keys
- Google Cloud credentials
- Azure client secrets
- GitHub tokens / PATs
- Private keys (RSA, EC, PEM)
- Database connection strings with passwords
- Generic high-entropy strings matching API key patterns

### Remediation

Never do this:

```dockerfile
# FAIL — credentials visible in docker history
ENV DB_PASSWORD=mysecretpassword
ARG API_KEY=sk-abc123xyz
RUN curl -H "Authorization: Bearer sk-abc123xyz" https://api.example.com
```

Instead:
1. **Build-time secrets (Docker BuildKit):**
   ```dockerfile
   # Mount secrets at build time — not stored in layers
   RUN --mount=type=secret,id=mysecret cat /run/secrets/mysecret
   ```
   ```bash
   docker build --secret id=mysecret,src=./mysecret.txt .
   ```

2. **Runtime environment variables** (injected by orchestrator, not baked in):
   ```bash
   docker run -e DB_PASSWORD=$DB_PASSWORD myapp
   # or via Docker Swarm/Kubernetes secrets
   ```

3. **Secrets management integration:**
   - HashiCorp Vault
   - AWS Secrets Manager
   - Azure Key Vault
   - Kubernetes Secrets (+ sealed-secrets or external-secrets)

---

## 4.11 — Only install verified packages

**Control ID:** CIS-DI-0011  
**CIS Section:** 4.11  
**Level:** L2

### Description

Package installations should verify GPG signatures or checksums to prevent
installation of tampered packages.

### Rationale

Without verification, apt/yum could install a package that has been tampered with
in a man-in-the-middle attack or compromised mirror.

### Remediation

Most modern package managers verify signatures by default. To enforce:

```dockerfile
# Debian/Ubuntu — signatures verified by default
RUN apt-get update && apt-get install -y \
    --no-install-recommends \
    --allow-unauthenticated=false \
    nginx

# Alpine — use SHA256 pinned packages
RUN apk add --no-cache nginx=1.24.0-r1
```

For pip:
```dockerfile
# Pin to hash
RUN pip install requests==2.31.0 --hash=sha256:abcd1234...
```

---

## Additional Image Checks

Beyond Section 4, Trivy also checks for OS-level CIS benchmarks based on the
image's operating system:

### Ubuntu CIS Benchmark
For images based on Ubuntu, checks include:
- Filesystem configuration (separate /tmp, /var/tmp partitions)
- Software updates enabled
- Auditd configured
- SSH hardening
- Password policies

### Alpine CIS Benchmark
For Alpine-based images, checks include:
- Minimal package set
- Read-only root filesystem capability
- No shell in production images

### Red Hat / CentOS CIS Benchmark
For RHEL/CentOS-based images:
- SELinux policies
- Firewall configuration
- Auditd setup
- Password complexity

---

## Severity Rating Guidelines

When evaluating findings, apply this prioritization:

| Severity | CVSS Score | Response Time | Description |
|----------|-----------|---------------|-------------|
| CRITICAL | 9.0–10.0 | Immediate — block deployment | Remote code execution, privilege escalation with public exploits |
| HIGH | 7.0–8.9 | Within 7 days | Significant impact, commonly exploited |
| MEDIUM | 4.0–6.9 | Within 30 days | Moderate impact, requires special conditions |
| LOW | 0.1–3.9 | Next release cycle | Minor impact, unlikely to be exploited |
| INFO/Unknown | — | Review and document | Informational, insufficient data |

### Exploitability Factors to Consider

When prioritizing MEDIUM/HIGH findings:
- **Has a public exploit (PoC)?** Treat as one severity level higher
- **Is the vulnerable component directly exposed to the internet?** Higher priority
- **Is the vulnerability in a path reachable by user input?** Higher priority
- **Does a fix exist?** No-fix vulnerabilities may require mitigation controls

---

## CI/CD Integration

Add container scanning to your CI/CD pipeline:

### GitHub Actions

```yaml
- name: Scan container image
  uses: aquasecurity/trivy-action@master
  with:
    image-ref: myapp:${{ github.sha }}
    format: 'sarif'
    output: 'trivy-results.sarif'
    severity: 'CRITICAL,HIGH'
    exit-code: '1'

- name: Upload results to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: 'trivy-results.sarif'
```

### GitLab CI

```yaml
container-scan:
  image: aquasec/trivy:latest
  script:
    - trivy image --exit-code 1 --severity CRITICAL $CI_REGISTRY_IMAGE:$CI_COMMIT_SHA
  allow_failure: false
```

### Jenkins

```groovy
stage('Security Scan') {
    steps {
        sh 'trivy image --exit-code 1 --severity CRITICAL,HIGH ${IMAGE_NAME}:${BUILD_NUMBER}'
    }
}
```

### Pre-deployment Gate Policy

Recommended gate policy:
- **Block:** Any CRITICAL CVE or CRITICAL misconfiguration
- **Warn:** HIGH CVEs (require sign-off)
- **Allow:** MEDIUM and below (log for tracking)
- **Block:** Any exposed secret (zero tolerance)
