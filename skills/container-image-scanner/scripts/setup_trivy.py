#!/usr/bin/env python3
"""
Trivy 本地化安装与管理工具

支持四种安装方式（优先级从高到低）：
  1. 已在系统 PATH 中 / ~/.local/bin/trivy 存在 → 直接使用
  2. --local-binary  指定本地已有 trivy 可执行文件路径
  3. --local-archive 指定本地 trivy tarball（trivy_*.tar.gz）
  4. --pkg-manager   使用系统包管理器（apt/yum/brew，需要已配置本地源）
  5. 网络下载（仅在明确传入 --download 时才联网）

漏洞数据库管理：
  - 默认使用本地缓存的 DB，不自动联网更新
  - --update-db         联网更新漏洞库（需要网络）
  - --db-archive PATH   从本地 tar.gz 导入 DB（离线迁移场景）
  - --cache-dir PATH    自定义 DB 缓存目录

用法示例：
  # 检查现有安装和 DB 状态
  python3 scripts/setup_trivy.py --check

  # 从本地可执行文件安装
  python3 scripts/setup_trivy.py --local-binary /tmp/trivy

  # 从本地 tarball 安装
  python3 scripts/setup_trivy.py --local-archive /tmp/trivy_0.69.3_Linux-64bit.tar.gz

  # 离线导入 DB
  python3 scripts/setup_trivy.py --db-archive /mnt/usb/trivy-db.tar.gz

  # 联网下载（仅在有网络时使用）
  python3 scripts/setup_trivy.py --download
  python3 scripts/setup_trivy.py --download --update-db
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


TRIVY_VERSION = "0.69.3"
INSTALL_DIR   = Path.home() / ".local" / "bin"
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "trivy"
DB_SUBDIR     = "db"
DB_FILE       = "trivy.db"
DB_METADATA   = "metadata.json"

# DB 最大可接受的年龄（天）—— 超过则在 --check 时发出警告
DB_MAX_AGE_DAYS = 7


# ---------------------------------------------------------------------------
# 查找 / 验证
# ---------------------------------------------------------------------------

def find_trivy(extra_paths: list[str] = None) -> str | None:
    """在 PATH、~/.local/bin 及 extra_paths 中查找 trivy 可执行文件。"""
    candidates = []
    if extra_paths:
        candidates.extend(extra_paths)
    candidates.append(str(INSTALL_DIR / "trivy"))

    # 先查 PATH
    found = shutil.which("trivy")
    if found:
        return found

    for path in candidates:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return path
    return None


def get_trivy_version(trivy_bin: str) -> str:
    result = subprocess.run([trivy_bin, "--version"],
                            capture_output=True, text=True)
    if result.returncode == 0:
        return result.stdout.strip().splitlines()[0]
    return "unknown"


def get_db_info(cache_dir: Path) -> dict:
    """返回 DB 状态信息，字段：exists, age_days, updated_at, next_update。"""
    meta_path = cache_dir / DB_SUBDIR / DB_METADATA
    db_path   = cache_dir / DB_SUBDIR / DB_FILE

    if not db_path.exists():
        return {"exists": False}

    info: dict = {"exists": True, "path": str(db_path),
                  "size_mb": round(db_path.stat().st_size / 1024 / 1024, 1)}

    if meta_path.exists():
        try:
            with open(meta_path, encoding="utf-8") as f:
                meta = json.load(f)
            updated_at  = meta.get("UpdatedAt", "")
            next_update = meta.get("NextUpdate", "")
            info["updated_at"]  = updated_at
            info["next_update"] = next_update
            if updated_at:
                dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                age = (datetime.now(timezone.utc) - dt).days
                info["age_days"] = age
        except Exception:
            pass

    return info


# ---------------------------------------------------------------------------
# 安装方式
# ---------------------------------------------------------------------------

def _get_platform() -> tuple[str, str]:
    system  = platform.system().lower()
    machine = platform.machine().lower()
    os_name = {"linux": "Linux", "darwin": "macOS"}.get(system)
    if not os_name:
        raise RuntimeError(f"不支持的操作系统: {system}")
    arch = {"x86_64": "64bit", "amd64": "64bit",
            "aarch64": "ARM64", "arm64": "ARM64"}.get(machine)
    if not arch:
        raise RuntimeError(f"不支持的架构: {machine}")
    return os_name, arch


def install_from_local_binary(src_path: str) -> str:
    """将指定的 trivy 可执行文件复制到安装目录。"""
    if not os.path.isfile(src_path):
        raise RuntimeError(f"文件不存在: {src_path}")
    if not os.access(src_path, os.X_OK):
        raise RuntimeError(f"文件无执行权限: {src_path}")

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    dest = str(INSTALL_DIR / "trivy")
    shutil.copy2(src_path, dest)
    os.chmod(dest, 0o755)
    print(f"已安装 trivy → {dest}")
    return dest


def install_from_local_archive(archive_path: str) -> str:
    """从本地 tar.gz 包安装 trivy。"""
    if not os.path.isfile(archive_path):
        raise RuntimeError(f"归档文件不存在: {archive_path}")

    INSTALL_DIR.mkdir(parents=True, exist_ok=True)
    dest = str(INSTALL_DIR / "trivy")

    with tempfile.TemporaryDirectory() as tmpdir:
        with tarfile.open(archive_path, "r:gz") as tar:
            # 只提取名为 "trivy" 的文件
            members = [m for m in tar.getmembers()
                       if os.path.basename(m.name) == "trivy"]
            if not members:
                raise RuntimeError("归档中未找到 trivy 可执行文件")
            member = members[0]
            member.name = "trivy"  # 确保提取到顶层
            tar.extract(member, path=tmpdir)

        extracted = os.path.join(tmpdir, "trivy")
        shutil.move(extracted, dest)
        os.chmod(dest, 0o755)

    print(f"已从归档安装 trivy → {dest}")
    return dest


def install_from_pkg_manager() -> str:
    """尝试用系统包管理器安装 trivy（需要预先配置了本地/内网源）。"""
    system = platform.system().lower()

    if system == "linux":
        for mgr, cmd in [
            ("apt-get", ["apt-get", "install", "-y", "trivy"]),
            ("yum",     ["yum", "install", "-y", "trivy"]),
            ("dnf",     ["dnf", "install", "-y", "trivy"]),
            ("apk",     ["apk", "add", "--no-network", "trivy"]),
        ]:
            if shutil.which(mgr):
                print(f"使用 {mgr} 安装 trivy...")
                result = subprocess.run(cmd, text=True)
                if result.returncode == 0:
                    found = shutil.which("trivy")
                    if found:
                        print(f"安装成功: {found}")
                        return found
                print(f"{mgr} 安装失败，尝试下一个...")
    elif system == "darwin":
        if shutil.which("brew"):
            result = subprocess.run(["brew", "install", "trivy"], text=True)
            if result.returncode == 0:
                found = shutil.which("trivy")
                if found:
                    return found

    raise RuntimeError("包管理器安装失败，请手动安装 trivy 或使用 --local-binary/--local-archive")


def install_from_network(version: str = TRIVY_VERSION) -> str:
    """从网络下载安装（仅在有网络时使用）。"""
    import urllib.request

    os_name, arch = _get_platform()
    filename = f"trivy_{version}_{os_name}-{arch}.tar.gz"
    url = (f"https://github.com/aquasecurity/trivy/releases/download/"
           f"v{version}/{filename}")

    print(f"从网络下载 Trivy {version} ({os_name}/{arch})...")
    print(f"URL: {url}")
    INSTALL_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmpdir:
        archive_path = os.path.join(tmpdir, filename)
        try:
            urllib.request.urlretrieve(url, archive_path)
        except Exception as e:
            raise RuntimeError(f"下载失败: {e}") from e
        return install_from_local_archive(archive_path)


# ---------------------------------------------------------------------------
# 数据库管理
# ---------------------------------------------------------------------------

def import_db_from_archive(archive_path: str, cache_dir: Path) -> None:
    """
    从本地 tar.gz 包导入漏洞数据库（离线迁移场景）。
    预期 archive 结构：
      trivy-db.tar.gz
        trivy.db
        metadata.json
    或由 prepare_offline.py 生成的标准格式。
    """
    if not os.path.isfile(archive_path):
        raise RuntimeError(f"DB 归档不存在: {archive_path}")

    db_dir = cache_dir / DB_SUBDIR
    db_dir.mkdir(parents=True, exist_ok=True)

    print(f"从归档导入漏洞数据库: {archive_path}")
    with tarfile.open(archive_path, "r:gz") as tar:
        members = tar.getmembers()
        for m in members:
            # 允许带或不带子目录前缀
            basename = os.path.basename(m.name)
            if basename in (DB_FILE, DB_METADATA):
                m.name = basename
                tar.extract(m, path=str(db_dir))
                print(f"  提取: {basename} ({m.size // 1024 // 1024} MB)")

    db_path = db_dir / DB_FILE
    if not db_path.exists():
        raise RuntimeError(
            f"导入后未找到 {DB_FILE}，请检查归档格式。"
            f"期望文件: {DB_FILE}, {DB_METADATA}"
        )
    print(f"数据库导入完成，路径: {db_dir}")


def update_db_online(trivy_bin: str, cache_dir: Path) -> None:
    """联网更新漏洞库（需要网络访问）。"""
    print("联网更新漏洞数据库...")
    cmd = [trivy_bin, "image", "--download-db-only", "--no-progress",
           "--cache-dir", str(cache_dir)]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"DB 更新失败:\n{result.stderr}")
    print("数据库更新完成。")


# ---------------------------------------------------------------------------
# 状态检查
# ---------------------------------------------------------------------------

def check_status(cache_dir: Path) -> dict:
    """检查 Trivy 安装和 DB 状态，返回状态摘要。"""
    status = {}
    trivy_bin = find_trivy()

    if trivy_bin:
        status["trivy_path"]    = trivy_bin
        status["trivy_version"] = get_trivy_version(trivy_bin)
        status["trivy_ok"]      = True
    else:
        status["trivy_ok"]      = False

    db_info = get_db_info(cache_dir)
    status["db"] = db_info

    if db_info.get("exists"):
        age = db_info.get("age_days", 0)
        status["db_ok"]     = True
        status["db_stale"]  = age > DB_MAX_AGE_DAYS
    else:
        status["db_ok"]    = False
        status["db_stale"] = False

    status["ready_for_offline_scan"] = status["trivy_ok"] and status["db_ok"]
    return status


def print_status(status: dict) -> None:
    print("\n" + "=" * 60)
    print("Trivy 本地化状态检查")
    print("=" * 60)

    if status["trivy_ok"]:
        print(f"✅ Trivy 二进制  : {status['trivy_path']}")
        print(f"   版本           : {status['trivy_version']}")
    else:
        print("❌ Trivy 二进制  : 未找到")
        print("   解决方案:")
        print("   - 系统包管理器 : python3 setup_trivy.py --pkg-manager")
        print("   - 本地文件     : python3 setup_trivy.py --local-binary /path/to/trivy")
        print("   - 本地归档     : python3 setup_trivy.py --local-archive /path/to/trivy.tar.gz")
        print("   - 网络下载     : python3 setup_trivy.py --download")

    db = status.get("db", {})
    if db.get("exists"):
        age = db.get("age_days", "未知")
        updated = db.get("updated_at", "未知")[:19]
        next_upd = db.get("next_update", "未知")[:19]
        stale_flag = " ⚠️ (过期，建议更新)" if status.get("db_stale") else ""
        print(f"\n{'✅' if not status.get('db_stale') else '⚠️'} 漏洞数据库    : {db['path']}")
        print(f"   大小           : {db.get('size_mb', '?')} MB")
        print(f"   最后更新       : {updated}{stale_flag}")
        print(f"   下次更新时间   : {next_upd}")
        print(f"   DB 年龄        : {age} 天")
    else:
        print("\n❌ 漏洞数据库    : 未找到")
        print("   解决方案:")
        print("   - 离线导入     : python3 setup_trivy.py --db-archive /path/to/trivy-db.tar.gz")
        print("   - 联网下载     : python3 setup_trivy.py --update-db")
        print("   - 打包工具     : python3 scripts/prepare_offline.py --package /tmp/trivy-bundle")

    print()
    if status["ready_for_offline_scan"]:
        print("✅ 已就绪：可执行离线扫描（无需网络）")
    else:
        print("❌ 未就绪：请先安装 Trivy 并导入漏洞数据库")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Trivy 本地化安装与 DB 管理工具（支持离线/内网环境）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    install_group = parser.add_mutually_exclusive_group()
    install_group.add_argument("--local-binary",  metavar="PATH",
                               help="从本地可执行文件安装 trivy")
    install_group.add_argument("--local-archive", metavar="PATH",
                               help="从本地 tar.gz 归档安装 trivy")
    install_group.add_argument("--pkg-manager",   action="store_true",
                               help="使用系统包管理器安装（需要配置内网源）")
    install_group.add_argument("--download",       action="store_true",
                               help="从网络下载安装（需要公网访问）")

    parser.add_argument("--update-db",   action="store_true",
                        help="联网更新漏洞数据库（需要网络）")
    parser.add_argument("--db-archive",  metavar="PATH",
                        help="从本地 tar.gz 归档导入漏洞数据库（离线）")
    parser.add_argument("--cache-dir",   default=str(DEFAULT_CACHE_DIR),
                        help=f"Trivy 缓存目录（默认: {DEFAULT_CACHE_DIR}）")
    parser.add_argument("--check",       action="store_true",
                        help="仅检查当前状态，不做任何安装")
    parser.add_argument("--version",     default=TRIVY_VERSION,
                        help=f"下载的 Trivy 版本（默认: {TRIVY_VERSION}）")

    args = parser.parse_args()
    cache_dir = Path(args.cache_dir)

    # ── 仅检查状态 ────────────────────────────────────────────
    if args.check:
        status = check_status(cache_dir)
        print_status(status)
        sys.exit(0 if status["ready_for_offline_scan"] else 1)

    # ── 安装 Trivy 二进制 ─────────────────────────────────────
    trivy_bin = find_trivy()

    if args.local_binary:
        trivy_bin = install_from_local_binary(args.local_binary)
    elif args.local_archive:
        trivy_bin = install_from_local_archive(args.local_archive)
    elif args.pkg_manager:
        trivy_bin = install_from_pkg_manager()
    elif args.download:
        if trivy_bin:
            print(f"Trivy 已存在: {trivy_bin}（{get_trivy_version(trivy_bin)}）")
            print("跳过下载。如需强制重装，请先删除现有二进制文件。")
        else:
            trivy_bin = install_from_network(args.version)
    elif not trivy_bin:
        # 无任何安装参数且未找到 trivy
        print("❌ 未找到 trivy，且未指定安装方式。")
        print("   请运行 `python3 setup_trivy.py --check` 查看详细安装指引。")
        sys.exit(1)

    if not trivy_bin:
        print("❌ Trivy 安装失败", file=sys.stderr)
        sys.exit(1)

    print(f"\nTrivy: {trivy_bin}  版本: {get_trivy_version(trivy_bin)}")

    # ── 数据库管理 ────────────────────────────────────────────
    if args.db_archive:
        import_db_from_archive(args.db_archive, cache_dir)
    elif args.update_db:
        update_db_online(trivy_bin, cache_dir)
    else:
        # 检查 DB 是否存在，给出建议但不强制更新
        db_info = get_db_info(cache_dir)
        if not db_info.get("exists"):
            print("\n⚠️  漏洞数据库未找到。离线扫描结果将无 CVE 数据。")
            print("   导入方式:")
            print("     离线: python3 setup_trivy.py --db-archive /path/to/trivy-db.tar.gz")
            print("     联网: python3 setup_trivy.py --update-db")
        elif db_info.get("age_days", 0) > DB_MAX_AGE_DAYS:
            print(f"\n⚠️  数据库已有 {db_info['age_days']} 天未更新（建议 {DB_MAX_AGE_DAYS} 天内更新）。")
            print("   如需更新: python3 setup_trivy.py --update-db")
        else:
            print(f"\n✅ 漏洞数据库正常（{db_info.get('age_days',0)} 天前更新）。")

    # 添加 ~/.local/bin 到 PATH 提示
    if str(INSTALL_DIR) not in os.environ.get("PATH", ""):
        print(f"\n提示: 请将 {INSTALL_DIR} 加入 PATH：")
        print(f"  echo 'export PATH=\"{INSTALL_DIR}:$PATH\"' >> ~/.bashrc && source ~/.bashrc")

    # 最终状态
    print()
    status = check_status(cache_dir)
    print_status(status)
    return trivy_bin


if __name__ == "__main__":
    main()
