#!/usr/bin/env python3
"""
交互式配置向导
引导用户完成代理、Token、项目列表等配置。

用法:
    python3 scripts/setup_config.py
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from config import TrackerConfig, CONFIG_FILE, DEFAULT_TRACKED_REPOS


def ask(prompt: str, default: str = "") -> str:
    if default:
        val = input(f"{prompt} [{default}]: ").strip()
        return val or default
    return input(f"{prompt}: ").strip()


def ask_yn(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    val = input(f"{prompt} {suffix}: ").strip().lower()
    if not val:
        return default
    return val in ("y", "yes", "是", "1")


def main():
    print("=" * 60)
    print("Go Security Tracker — 配置向导")
    print("=" * 60)
    print()

    cfg = TrackerConfig.load()

    # 代理配置
    print("【1/5】代理配置")
    print("  当前环境变量代理：")
    env_proxy = (os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or
                 os.environ.get("ALL_PROXY") or "未设置")
    print(f"    HTTPS_PROXY / HTTP_PROXY = {env_proxy}")
    print()

    use_proxy = ask_yn("是否需要配置固定代理（推荐使用环境变量）", default=bool(cfg.proxy.https_proxy))
    if use_proxy:
        proxy_url = ask("代理地址", cfg.proxy.https_proxy or "http://proxy.company.com:8080")
        cfg.proxy.https_proxy = proxy_url
        cfg.proxy.http_proxy = proxy_url

        ca_bundle = ask("企业 CA 证书路径（可选，直接回车跳过）", cfg.proxy.ca_bundle or "")
        if ca_bundle:
            cfg.proxy.ca_bundle = ca_bundle

        verify_ssl = ask_yn("是否验证 SSL 证书（推荐 yes）", cfg.proxy.verify_ssl)
        cfg.proxy.verify_ssl = verify_ssl
    else:
        cfg.proxy.https_proxy = None
        cfg.proxy.http_proxy = None

    print()

    # GitHub Token
    print("【2/5】GitHub Token（可选，用于获取更多安全公告，提高 API 限速）")
    print("  获取方式: GitHub Settings → Developer settings → Personal access tokens")
    print("  所需权限: 只需 public_repo read 即可（或无任何权限的 Fine-grained token）")
    print(f"  当前: {'已配置' if cfg.github_token else '未配置'}")
    use_token = ask_yn("是否配置 GitHub Token", default=bool(cfg.github_token))
    if use_token:
        token = ask("GitHub Token（输入后不会显示）", "")
        if not token:
            token = input("GitHub Token: ").strip()
        if token:
            cfg.github_token = token
    print()

    # 输出目录
    print("【3/5】输出目录配置")
    output_dir = ask("报告输出目录", cfg.output_dir)
    cfg.output_dir = output_dir
    print()

    # 语言设置
    print("【4/5】报告语言")
    print("  zh = 中文（默认）  en = English")
    lang = ask("语言", cfg.language)
    cfg.language = lang if lang in ("zh", "en") else "zh"
    print()

    # 追踪项目
    print("【5/5】追踪项目列表")
    print(f"  默认追踪 {len(DEFAULT_TRACKED_REPOS)} 个项目：")
    for repo in DEFAULT_TRACKED_REPOS[:5]:
        print(f"    - {repo}")
    print(f"    ... 共 {len(DEFAULT_TRACKED_REPOS)} 个（详见 references/tracked_projects.md）")

    use_default = ask_yn("使用默认项目列表", default=True)
    if not use_default:
        print("输入自定义项目（格式 owner/repo，每行一个，空行结束）：")
        repos = []
        while True:
            line = input("> ").strip()
            if not line:
                break
            if "/" in line:
                repos.append(line)
        if repos:
            cfg.tracked_repos = repos
            print(f"已配置 {len(repos)} 个自定义项目")
    print()

    # 保存
    print("=" * 60)
    print("配置摘要：")
    print(f"  代理: {cfg.proxy.https_proxy or '未使用'}")
    print(f"  GitHub Token: {'已配置' if cfg.github_token else '未配置'}")
    print(f"  输出目录: {cfg.output_dir}")
    print(f"  语言: {cfg.language}")
    print(f"  追踪项目数: {len(cfg.tracked_repos)}")
    print("=" * 60)

    save = ask_yn("保存配置", default=True)
    if save:
        cfg.save()
        print(f"\n✅ 配置已保存到: {CONFIG_FILE}")
        print("\n接下来可以运行：")
        print("  python3 scripts/check_proxy.py     # 验证连通性")
        print("  python3 scripts/run_daily.py        # 生成今日报告")
    else:
        print("配置未保存")


if __name__ == "__main__":
    main()
