#!/usr/bin/env python3
"""
离线包打包工具

在有网络的机器上运行，将以下内容打包为可移植的离线包：
  1. Trivy 二进制文件
  2. 漏洞数据库（~/.cache/trivy/db/）
  3. 检查规则/策略文件（~/.cache/trivy/policy/）

打包后生成一个 .tar.gz 文件，可以复制到内网/离线环境并通过
setup_trivy.py 导入。

用法示例：
  # 打包（需要网络 + trivy 已安装 + DB 已下载）
  python3 scripts/prepare_offline.py --package /tmp/trivy-offline-bundle

  # 可选：同时下载 Trivy 并更新 DB
  python3 scripts/prepare_offline.py --package /tmp/bundle --update-db

  # 在离线机器上导入（无需网络）
  python3 scripts/setup_trivy.py --local-archive /tmp/bundle/trivy_Linux-64bit.tar.gz
  python3 scripts/setup_trivy.py --db-archive /tmp/bundle/trivy-db.tar.gz
"""

import argparse
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CACHE_DIR = Path.home() / ".cache" / "trivy"
INSTALL_DIR       = Path.home() / ".local" / "bin"
TRIVY_VERSION     = "0.69.3"


def find_trivy() -> str | None:
    p = shutil.which("trivy")
    if p:
        return p
    local = INSTALL_DIR / "trivy"
    return str(local) if local.is_file() else None


def _get_platform() -> tuple[str, str]:
    system  = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "Linux", "darwin": "macOS"}.get(system, "Linux")
    arch    = {"x86_64": "64bit", "amd64": "64bit",
               "aarch64": "ARM64", "arm64": "ARM64"}.get(machine, "64bit")
    return os_name, arch


def download_trivy_if_needed(version: str) -> str:
    """确保 trivy 已安装，必要时从网络下载。"""
    trivy_bin = find_trivy()
    if trivy_bin:
        print(f"  使用现有 trivy: {trivy_bin}")
        return trivy_bin

    import urllib.request
    os_name, arch = _get_platform()
    filename = f"trivy_{version}_{os_name}-{arch}.tar.gz"
    url = (f"https://github.com/aquasecurity/trivy/releases/download/"
           f"v{version}/{filename}")

    print(f"  从网络下载 trivy {version}...")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive = os.path.join(tmpdir, filename)
        urllib.request.urlretrieve(url, archive)
        with tarfile.open(archive, "r:gz") as tar:
            members = [m for m in tar.getmembers()
                       if os.path.basename(m.name) == "trivy"]
            if members:
                members[0].name = "trivy"
                tar.extract(members[0], path=tmpdir)
        dest = str(INSTALL_DIR / "trivy")
        shutil.move(os.path.join(tmpdir, "trivy"), dest)
        os.chmod(dest, 0o755)

    print(f"  trivy 已安装: {dest}")
    return dest


def update_db(trivy_bin: str, cache_dir: Path) -> None:
    """联网更新漏洞库。"""
    print("  联网下载漏洞数据库...")
    result = subprocess.run(
        [trivy_bin, "image", "--download-db-only", "--no-progress",
         "--cache-dir", str(cache_dir)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"DB 下载失败:\n{result.stderr}")
    print("  漏洞数据库下载完成。")


def get_db_info(cache_dir: Path) -> dict:
    meta_path = cache_dir / "db" / "metadata.json"
    db_path   = cache_dir / "db" / "trivy.db"
    if not db_path.exists():
        return {}
    info = {"db_path": str(db_path), "size_mb": round(db_path.stat().st_size / 1024 / 1024, 1)}
    if meta_path.exists():
        with open(meta_path, encoding="utf-8") as f:
            meta = json.load(f)
        info.update({"updated_at": meta.get("UpdatedAt", ""), "version": meta.get("Version", "")})
    return info


def package_binary(trivy_bin: str, output_dir: Path) -> str:
    """将 trivy 二进制文件打包为 tar.gz。"""
    os_name, arch = _get_platform()
    archive_name = f"trivy_{os_name}-{arch}.tar.gz"
    archive_path = str(output_dir / archive_name)

    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(trivy_bin, arcname="trivy")

    size_mb = round(os.path.getsize(archive_path) / 1024 / 1024, 1)
    print(f"  Trivy 二进制包: {archive_path} ({size_mb} MB)")
    return archive_path


def package_db(cache_dir: Path, output_dir: Path) -> str:
    """将漏洞数据库打包为 tar.gz。"""
    db_dir       = cache_dir / "db"
    archive_path = str(output_dir / "trivy-db.tar.gz")

    if not (db_dir / "trivy.db").exists():
        raise RuntimeError(f"漏洞数据库不存在: {db_dir}\n"
                           "请先运行: python3 prepare_offline.py --update-db")

    with tarfile.open(archive_path, "w:gz") as tar:
        for fname in ("trivy.db", "metadata.json"):
            fpath = db_dir / fname
            if fpath.exists():
                tar.add(str(fpath), arcname=fname)

    size_mb = round(os.path.getsize(archive_path) / 1024 / 1024, 1)
    print(f"  漏洞数据库包: {archive_path} ({size_mb} MB)")
    return archive_path


def package_policy(cache_dir: Path, output_dir: Path) -> str | None:
    """打包 CIS/Dockerfile 检查策略文件（如果存在）。"""
    policy_dir = cache_dir / "policy"
    if not policy_dir.exists():
        return None

    archive_path = str(output_dir / "trivy-policy.tar.gz")
    with tarfile.open(archive_path, "w:gz") as tar:
        tar.add(str(policy_dir), arcname="policy")

    size_mb = round(os.path.getsize(archive_path) / 1024 / 1024, 1)
    print(f"  策略文件包: {archive_path} ({size_mb} MB)")
    return archive_path


def write_manifest(output_dir: Path, info: dict) -> str:
    """写入包清单文件（包含版本、校验信息等）。"""
    manifest_path = str(output_dir / "offline-manifest.json")
    manifest = {
        "created_at":    datetime.now(timezone.utc).isoformat(),
        "trivy_version": info.get("trivy_version", ""),
        "db_updated_at": info.get("db_updated_at", ""),
        "db_version":    info.get("db_version", ""),
        "platform":      f"{platform.system()}-{platform.machine()}",
        "files": info.get("files", []),
        "import_commands": {
            "trivy_binary": "python3 scripts/setup_trivy.py --local-archive trivy_*.tar.gz",
            "vuln_db":      "python3 scripts/setup_trivy.py --db-archive trivy-db.tar.gz",
            "verify":       "python3 scripts/setup_trivy.py --check",
            "scan_example": "python3 scripts/scan_image.py --input myimage.tar --output-dir ./report",
        },
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=False)
    print(f"  清单文件: {manifest_path}")
    return manifest_path


def print_import_instructions(output_dir: Path) -> None:
    print(f"\n{'='*60}")
    print("离线包已生成，在目标机器上执行以下步骤导入：")
    print(f"{'='*60}")
    print()
    print("# 步骤 1: 将整个 bundle 目录复制到目标机器")
    print(f"#  scp -r {output_dir} user@target:/tmp/trivy-bundle")
    print()
    print("# 步骤 2: 在目标机器上安装 Trivy 二进制")
    print(f"  python3 scripts/setup_trivy.py --local-archive /tmp/trivy-bundle/trivy_*.tar.gz")
    print()
    print("# 步骤 3: 导入漏洞数据库")
    print(f"  python3 scripts/setup_trivy.py --db-archive /tmp/trivy-bundle/trivy-db.tar.gz")
    print()
    print("# 步骤 4: 验证安装")
    print("  python3 scripts/setup_trivy.py --check")
    print()
    print("# 步骤 5: 扫描（完全离线）")
    print("  # 从本地 Docker daemon 扫描已有镜像：")
    print("  python3 scripts/scan_image.py --image nginx:latest --output-dir ./report")
    print("  # 扫描本地 tar 包（完全不需要 Docker）：")
    print("  docker save nginx:latest -o nginx.tar")
    print("  python3 scripts/scan_image.py --input nginx.tar --output-dir ./report")
    print(f"{'='*60}\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="生成 Trivy 离线部署包（在有网络的机器上运行）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--package",    required=True, metavar="DIR",
                        help="输出目录（将在此目录下生成所有打包文件）")
    parser.add_argument("--cache-dir",  default=str(DEFAULT_CACHE_DIR),
                        help=f"Trivy 缓存目录（默认: {DEFAULT_CACHE_DIR}）")
    parser.add_argument("--update-db",  action="store_true",
                        help="打包前先联网更新漏洞库")
    parser.add_argument("--version",    default=TRIVY_VERSION,
                        help=f"Trivy 版本（默认: {TRIVY_VERSION}）")
    parser.add_argument("--no-binary",  action="store_true",
                        help="不打包 Trivy 二进制（只打包 DB）")
    args = parser.parse_args()

    output_dir = Path(args.package)
    output_dir.mkdir(parents=True, exist_ok=True)
    cache_dir  = Path(args.cache_dir)

    print(f"\n{'='*60}")
    print("Trivy 离线包打包工具")
    print(f"{'='*60}")
    print(f"输出目录  : {output_dir}")
    print(f"缓存目录  : {cache_dir}")
    print(f"{'='*60}\n")

    packaged_files = []
    info: dict = {}

    # 1. Trivy 二进制
    if not args.no_binary:
        print("[1/3] 准备 Trivy 二进制...")
        trivy_bin = download_trivy_if_needed(args.version)
        result = subprocess.run([trivy_bin, "--version"],
                                capture_output=True, text=True)
        info["trivy_version"] = result.stdout.strip().splitlines()[0] if result.returncode == 0 else "unknown"
        binary_archive = package_binary(trivy_bin, output_dir)
        packaged_files.append(os.path.basename(binary_archive))
    else:
        print("[1/3] 跳过 Trivy 二进制（--no-binary）")
        trivy_bin = find_trivy()
        if not trivy_bin:
            print("  ⚠️  警告: 未找到 trivy，无法更新 DB")

    # 2. 漏洞数据库
    print("\n[2/3] 准备漏洞数据库...")
    if args.update_db and trivy_bin:
        update_db(trivy_bin, cache_dir)

    db_info = get_db_info(cache_dir)
    if db_info:
        info["db_updated_at"] = db_info.get("updated_at", "")
        info["db_version"]    = str(db_info.get("version", ""))
        print(f"  DB 最后更新: {db_info.get('updated_at', '未知')[:19]}")
        print(f"  DB 大小: {db_info.get('size_mb', '?')} MB")
        db_archive = package_db(cache_dir, output_dir)
        packaged_files.append(os.path.basename(db_archive))
    else:
        print("  ⚠️  漏洞数据库不存在，跳过打包。")
        print("     请先运行: python3 prepare_offline.py --package . --update-db")

    # 3. 策略文件（CIS 检查规则）
    print("\n[3/3] 打包策略文件...")
    policy_archive = package_policy(cache_dir, output_dir)
    if policy_archive:
        packaged_files.append(os.path.basename(policy_archive))
    else:
        print("  策略文件目录不存在，跳过（首次扫描时 Trivy 会自动生成）")

    # 写清单
    info["files"] = packaged_files
    write_manifest(output_dir, info)
    packaged_files.append("offline-manifest.json")

    # 显示结果
    print(f"\n{'='*60}")
    print("打包完成")
    print(f"{'='*60}")
    total_size = sum(
        Path(output_dir / f).stat().st_size
        for f in packaged_files
        if (output_dir / f).exists()
    )
    print(f"输出目录  : {output_dir}")
    print(f"文件列表  :")
    for f in packaged_files:
        fpath = output_dir / f
        if fpath.exists():
            size = round(fpath.stat().st_size / 1024 / 1024, 1)
            print(f"  {f:<40} {size:>7} MB")
    print(f"  {'合计':<40} {round(total_size/1024/1024, 1):>7} MB")

    print_import_instructions(output_dir)


if __name__ == "__main__":
    main()
