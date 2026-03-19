#!/usr/bin/env python3
"""
代理连通性检测工具
验证当前代理配置是否能访问各数据源。

用法:
    python3 scripts/check_proxy.py
    python3 scripts/check_proxy.py --proxy http://proxy.company.com:8080
"""

import argparse
import sys
import time
from pathlib import Path

import requests
import urllib3

sys.path.insert(0, str(Path(__file__).parent))
from config import TrackerConfig

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TEST_URLS = [
    ("Go 官方漏洞库",   "https://vuln.go.dev/index/vulns.json"),
    ("OSV.dev API",     "https://api.osv.dev/v1/query"),
    ("GitHub API",      "https://api.github.com/rate_limit"),
    ("NVD API",         "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"),
]


def check_url(session: requests.Session, name: str, url: str) -> dict:
    start = time.time()
    try:
        if "osv.dev" in url and "/query" in url:
            resp = session.post(url, json={"package": {"name": "stdlib", "ecosystem": "Go"}}, timeout=15)
        else:
            resp = session.get(url, timeout=15)
        elapsed = time.time() - start
        if resp.status_code < 400:
            return {"name": name, "url": url, "status": "✅ OK", "code": resp.status_code, "ms": int(elapsed * 1000)}
        else:
            return {"name": name, "url": url, "status": f"⚠️ HTTP {resp.status_code}", "code": resp.status_code, "ms": int(elapsed * 1000)}
    except requests.exceptions.ProxyError as e:
        return {"name": name, "url": url, "status": f"❌ 代理错误: {str(e)[:60]}", "code": 0, "ms": 0}
    except requests.exceptions.SSLError as e:
        return {"name": name, "url": url, "status": f"❌ SSL错误: {str(e)[:60]}", "code": 0, "ms": 0}
    except requests.exceptions.ConnectionError as e:
        return {"name": name, "url": url, "status": f"❌ 连接失败: {str(e)[:60]}", "code": 0, "ms": 0}
    except requests.exceptions.Timeout:
        return {"name": name, "url": url, "status": "❌ 超时", "code": 0, "ms": 15000}
    except Exception as e:
        return {"name": name, "url": url, "status": f"❌ 错误: {str(e)[:60]}", "code": 0, "ms": 0}


def main():
    parser = argparse.ArgumentParser(description="检测代理连通性")
    parser.add_argument("--proxy", help="代理地址（如: http://proxy.company.com:8080）")
    parser.add_argument("--no-verify-ssl", action="store_true", help="跳过 SSL 验证")
    args = parser.parse_args()

    cfg = TrackerConfig.load(override_proxy=args.proxy)
    if args.no_verify_ssl:
        cfg.proxy.verify_ssl = False

    print("=" * 60)
    print("Go Security Tracker — 代理连通性检测")
    print("=" * 60)

    proxy_cfg = cfg.proxy
    if proxy_cfg.https_proxy or proxy_cfg.http_proxy:
        print(f"代理地址 : HTTPS={proxy_cfg.https_proxy}  HTTP={proxy_cfg.http_proxy}")
        print(f"SSL 验证 : {proxy_cfg.verify_ssl}")
        if proxy_cfg.ca_bundle:
            print(f"CA Bundle: {proxy_cfg.ca_bundle}")
    else:
        print("代理配置 : 未使用代理（直连）")

    print(f"NO_PROXY : {proxy_cfg.no_proxy or '未设置'}")
    print()

    session = requests.Session()
    proxies = proxy_cfg.to_requests_proxies()
    if proxies:
        session.proxies.update(proxies)
    session.verify = proxy_cfg.to_requests_verify()
    session.headers["User-Agent"] = "go-security-tracker/1.0"

    results = []
    for name, url in TEST_URLS:
        print(f"检测 {name}...", end=" ", flush=True)
        result = check_url(session, name, url)
        print(result["status"])
        results.append(result)

    print()
    print("=" * 60)
    all_ok = all(r["code"] > 0 and r["code"] < 400 for r in results)
    if all_ok:
        print("✅ 所有数据源连接正常！可以运行 fetch_advisories.py")
    else:
        failed = [r for r in results if r["code"] == 0 or r["code"] >= 400]
        print(f"⚠️  {len(failed)} 个数据源连接失败：")
        for r in failed:
            print(f"   {r['name']}: {r['status']}")
        print()
        print("排查建议：")
        print("  1. 检查代理地址是否正确：export HTTPS_PROXY=http://proxy:8080")
        print("  2. SSL 证书问题：export REQUESTS_CA_BUNDLE=/path/to/ca.pem")
        print("  3. 禁用 SSL 验证（不推荐）：python3 check_proxy.py --no-verify-ssl")
        print("  4. NTLM 认证代理：pip install requests-ntlm 并配置 ~/.go-security-tracker/config.json")
        print("  5. SOCKS5 代理：export ALL_PROXY=socks5://proxy:1080")
    print("=" * 60)

    sys.exit(0 if all_ok else 1)


if __name__ == "__main__":
    main()
