#!/usr/bin/env python3
"""
Setup script for Trivy container security scanner.
Installs Trivy if not found and updates the vulnerability database.
"""

import os
import sys
import shutil
import subprocess
import platform
import urllib.request
import tarfile
import tempfile


TRIVY_VERSION = "0.69.3"
INSTALL_DIR = os.path.expanduser("~/.local/bin")


def find_trivy() -> str | None:
    """Return path to trivy binary if it exists, else None."""
    path = shutil.which("trivy")
    if path:
        return path
    local = os.path.join(INSTALL_DIR, "trivy")
    if os.path.isfile(local) and os.access(local, os.X_OK):
        return local
    return None


def get_platform_info() -> tuple[str, str]:
    """Return (os_name, arch) for download URL."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "linux":
        os_name = "Linux"
    elif system == "darwin":
        os_name = "macOS"
    else:
        raise RuntimeError(f"Unsupported OS: {system}")

    if machine in ("x86_64", "amd64"):
        arch = "64bit"
    elif machine in ("aarch64", "arm64"):
        arch = "ARM64"
    else:
        raise RuntimeError(f"Unsupported architecture: {machine}")

    return os_name, arch


def install_trivy() -> str:
    """Download and install Trivy, return path to binary."""
    os_name, arch = get_platform_info()
    filename = f"trivy_{TRIVY_VERSION}_{os_name}-{arch}.tar.gz"
    url = (
        f"https://github.com/aquasecurity/trivy/releases/download/"
        f"v{TRIVY_VERSION}/{filename}"
    )

    print(f"Downloading Trivy {TRIVY_VERSION} ({os_name}/{arch})...")
    os.makedirs(INSTALL_DIR, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = os.path.join(tmpdir, filename)
        try:
            urllib.request.urlretrieve(url, archive_path)
        except Exception as e:
            raise RuntimeError(f"Failed to download Trivy: {e}\nURL: {url}") from e

        with tarfile.open(archive_path, "r:gz") as tar:
            tar.extract("trivy", path=tmpdir)

        dest = os.path.join(INSTALL_DIR, "trivy")
        shutil.move(os.path.join(tmpdir, "trivy"), dest)
        os.chmod(dest, 0o755)

    print(f"Trivy installed to {dest}")
    return dest


def update_db(trivy_bin: str) -> None:
    """Update Trivy vulnerability database."""
    print("Updating Trivy vulnerability database...")
    result = subprocess.run(
        [trivy_bin, "image", "--download-db-only", "--no-progress"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"Warning: DB update failed (continuing anyway):\n{result.stderr}")
    else:
        print("Database updated successfully.")


def get_trivy_version(trivy_bin: str) -> str:
    """Return the installed Trivy version string."""
    result = subprocess.run(
        [trivy_bin, "--version"], capture_output=True, text=True
    )
    return result.stdout.strip().splitlines()[0] if result.returncode == 0 else "unknown"


def main():
    trivy_bin = find_trivy()

    if trivy_bin:
        print(f"Trivy found at: {trivy_bin}")
        version = get_trivy_version(trivy_bin)
        print(f"Version: {version}")
    else:
        print("Trivy not found. Installing...")
        try:
            trivy_bin = install_trivy()
            # Add to PATH for current process
            os.environ["PATH"] = INSTALL_DIR + os.pathsep + os.environ.get("PATH", "")
        except RuntimeError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            print(
                "\nManual install: https://aquasecurity.github.io/trivy/latest/getting-started/installation/",
                file=sys.stderr,
            )
            sys.exit(1)

    update_db(trivy_bin)
    print(f"\nSetup complete. Trivy binary: {trivy_bin}")
    return trivy_bin


if __name__ == "__main__":
    main()
