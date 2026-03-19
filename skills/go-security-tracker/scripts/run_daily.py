#!/usr/bin/env python3
"""
一键运行脚本：抓取 + 生成日报
适合配置为 cron 任务每日自动执行。

用法:
    python3 scripts/run_daily.py
    python3 scripts/run_daily.py --output-dir ~/go-security-reports --days 1
    python3 scripts/run_daily.py --proxy http://proxy.company.com:8080
    python3 scripts/run_daily.py --week   # 生成周报（最近7天）

Cron 示例（每天 8:00 运行，企业代理环境）:
    0 8 * * * cd /path/to/skill && HTTPS_PROXY=http://proxy:8080 \
        python3 scripts/run_daily.py --output-dir ~/go-security-reports >> ~/go-security-reports/cron.log 2>&1
"""

import argparse
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


def run_step(cmd: list[str], step_name: str) -> bool:
    """运行一个步骤，返回是否成功。"""
    print(f"\n{'─'*50}")
    print(f"步骤: {step_name}")
    print(f"命令: {' '.join(cmd)}")
    print(f"{'─'*50}")
    result = subprocess.run(cmd, text=True)
    if result.returncode != 0:
        print(f"⚠️  {step_name} 失败（退出码 {result.returncode}），继续执行后续步骤...")
        return False
    return True


def main():
    parser = argparse.ArgumentParser(description="Go 安全日报一键运行脚本")
    parser.add_argument("--output-dir", default="./go-security-reports", help="输出目录")
    parser.add_argument("--proxy", help="代理地址")
    parser.add_argument("--days", type=int, default=1, help="抓取天数（默认 1 天）")
    parser.add_argument("--week", action="store_true", help="生成周报（7天）")
    parser.add_argument("--format", choices=["html", "markdown", "both"], default="both")
    parser.add_argument("--no-verify-ssl", action="store_true", help="跳过 SSL 验证")
    parser.add_argument("--source", default="all", help="数据源")
    args = parser.parse_args()

    days = 7 if args.week else args.days
    output_dir = Path(args.output_dir)
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    raw_file = output_dir / "raw" / date_str / "advisories.json"

    scripts_dir = Path(__file__).parent
    python = sys.executable

    print(f"\n{'='*60}")
    print(f"Go 开源项目安全{'周报' if args.week else '日报'} — {date_str}")
    print(f"{'='*60}")
    print(f"输出目录: {output_dir}")
    print(f"时间范围: 最近 {days} 天")
    if args.proxy:
        print(f"代理配置: {args.proxy}")
    print(f"{'='*60}")

    # Step 1: 抓取
    fetch_cmd = [
        python,
        str(scripts_dir / "fetch_advisories.py"),
        "--days", str(days),
        "--output-dir", str(output_dir),
        "--source", args.source,
    ]
    if args.proxy:
        fetch_cmd += ["--proxy", args.proxy]
    if args.no_verify_ssl:
        fetch_cmd.append("--no-verify-ssl")

    fetch_ok = run_step(fetch_cmd, "抓取安全公告")

    # Step 2: 生成报告（即使抓取部分失败也尝试）
    if not raw_file.exists():
        print(f"\n⚠️  找不到原始数据文件: {raw_file}")
        print("抓取可能失败，无法生成报告")
        sys.exit(1)

    digest_cmd = [
        python,
        str(scripts_dir / "generate_digest.py"),
        "--raw-file", str(raw_file),
        "--output-dir", str(output_dir),
        "--format", args.format,
        "--date", date_str,
    ]
    digest_ok = run_step(digest_cmd, "生成安全日报")

    # 最终摘要
    print(f"\n{'='*60}")
    print(f"运行完成")
    print(f"{'='*60}")
    print(f"抓取:   {'✅ 成功' if fetch_ok else '⚠️  部分失败'}")
    print(f"报告:   {'✅ 成功' if digest_ok else '❌ 失败'}")

    if args.format in ("html", "both"):
        html_path = output_dir / f"go-security-digest-{date_str}.html"
        if html_path.exists():
            print(f"HTML:   {html_path}")

    if args.format in ("markdown", "both"):
        md_path = output_dir / f"go-security-digest-{date_str}.md"
        if md_path.exists():
            print(f"Markdown: {md_path}")

    print(f"{'='*60}\n")

    sys.exit(0 if (fetch_ok and digest_ok) else 1)


if __name__ == "__main__":
    main()
