"""
配置管理模块：读取代理设置、项目列表、API 密钥等。
支持环境变量、配置文件和命令行参数三层覆盖。
"""

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


CONFIG_DIR = Path.home() / ".go-security-tracker"
CONFIG_FILE = CONFIG_DIR / "config.json"

# 默认追踪的 Go 开源项目（GitHub owner/repo 格式）
DEFAULT_TRACKED_REPOS = [
    # 容器/编排
    "kubernetes/kubernetes",
    "moby/moby",
    "containerd/containerd",
    "helm/helm",
    "opencontainers/runc",
    # 服务网格/网络
    "istio/istio",
    "cilium/cilium",
    "traefik/traefik",
    # 数据库/存储
    "etcd-io/etcd",
    "pingcap/tidb",
    "cockroachdb/cockroach",
    # 密钥/认证
    "hashicorp/vault",
    "hashicorp/consul",
    "cert-manager/cert-manager",
    # 可观测性
    "prometheus/prometheus",
    "grafana/grafana",
    "open-telemetry/opentelemetry-go",
    # CI/CD
    "argoproj/argo-cd",
    "go-gitea/gitea",
    "fluxcd/flux2",
    # 运行时/标准库/工具链
    "golang/go",
    "grpc/grpc-go",
    "google/go-containerregistry",
    # API 网关/代理
    "envoyproxy/go-control-plane",
    "coredns/coredns",
]

# Go 漏洞类型分类
VULN_CATEGORIES = {
    "G-INJ":    "注入类（SQL/命令/模板/LDAP）",
    "G-AUTH":   "认证/授权绕过",
    "G-DOS":    "拒绝服务（DoS）",
    "G-MEM":    "内存安全",
    "G-PROTO":  "协议/序列化漏洞",
    "G-CRYPTO": "密码学问题",
    "G-SSRF":   "服务端请求伪造（SSRF）",
    "G-PATH":   "路径遍历",
    "G-RACE":   "竞争条件",
    "G-SUPPLY": "供应链安全",
    "G-OTHER":  "其他",
}


@dataclass
class ProxyConfig:
    http_proxy: Optional[str] = None
    https_proxy: Optional[str] = None
    no_proxy: Optional[str] = None
    verify_ssl: bool = True
    ca_bundle: Optional[str] = None

    def to_requests_proxies(self) -> dict:
        """返回 requests 库可直接使用的代理字典。"""
        proxies = {}
        p = self.https_proxy or self.http_proxy
        if p:
            proxies["http"] = self.http_proxy or p
            proxies["https"] = self.https_proxy or p
        return proxies

    def to_requests_verify(self):
        """返回 requests verify 参数值。"""
        if not self.verify_ssl:
            return False
        if self.ca_bundle:
            return self.ca_bundle
        return True


@dataclass
class TrackerConfig:
    tracked_repos: list[str] = field(default_factory=lambda: list(DEFAULT_TRACKED_REPOS))
    github_token: Optional[str] = None
    output_dir: str = "./go-security-reports"
    language: str = "zh"  # zh | en
    days_default: int = 1
    proxy: ProxyConfig = field(default_factory=ProxyConfig)

    @classmethod
    def load(cls, override_proxy: Optional[str] = None) -> "TrackerConfig":
        """从配置文件 + 环境变量加载配置，命令行代理参数优先级最高。"""
        cfg = cls()

        # 1. 读取配置文件
        if CONFIG_FILE.exists():
            try:
                with open(CONFIG_FILE, encoding="utf-8") as f:
                    data = json.load(f)
                cfg._apply_file_config(data)
            except Exception as e:
                print(f"Warning: failed to read config file {CONFIG_FILE}: {e}")

        # 2. 环境变量覆盖
        cfg._apply_env_vars()

        # 3. 命令行 --proxy 参数最高优先级
        if override_proxy:
            cfg.proxy.https_proxy = override_proxy
            cfg.proxy.http_proxy = override_proxy

        return cfg

    def _apply_file_config(self, data: dict) -> None:
        if "tracked_repos" in data:
            self.tracked_repos = data["tracked_repos"]
        if "github_token" in data:
            self.github_token = data["github_token"]
        if "output_dir" in data:
            self.output_dir = data["output_dir"]
        if "language" in data:
            self.language = data["language"]
        if "days_default" in data:
            self.days_default = data["days_default"]
        if "proxy" in data:
            p = data["proxy"]
            self.proxy.http_proxy = p.get("http_proxy")
            self.proxy.https_proxy = p.get("https_proxy")
            self.proxy.no_proxy = p.get("no_proxy")
            self.proxy.verify_ssl = p.get("verify_ssl", True)
            self.proxy.ca_bundle = p.get("ca_bundle")

    def _apply_env_vars(self) -> None:
        # GitHub token
        token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
        if token:
            self.github_token = token

        # 代理：自定义变量优先级最高，其次 HTTPS_PROXY，再次 HTTP_PROXY
        custom_proxy = os.environ.get("GO_SECURITY_PROXY")
        https_proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        http_proxy = os.environ.get("HTTP_PROXY") or os.environ.get("http_proxy")
        all_proxy = os.environ.get("ALL_PROXY") or os.environ.get("all_proxy")

        effective_proxy = custom_proxy or https_proxy or http_proxy or all_proxy
        if effective_proxy and not self.proxy.https_proxy:
            self.proxy.https_proxy = effective_proxy
        if http_proxy and not self.proxy.http_proxy:
            self.proxy.http_proxy = http_proxy

        no_proxy = os.environ.get("NO_PROXY") or os.environ.get("no_proxy")
        if no_proxy:
            self.proxy.no_proxy = no_proxy

        # SSL 证书
        ca_bundle = os.environ.get("REQUESTS_CA_BUNDLE") or os.environ.get("SSL_CERT_FILE")
        if ca_bundle:
            self.proxy.ca_bundle = ca_bundle

    def save(self) -> None:
        """保存当前配置到文件。"""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        data = {
            "tracked_repos": self.tracked_repos,
            "github_token": self.github_token,
            "output_dir": self.output_dir,
            "language": self.language,
            "days_default": self.days_default,
            "proxy": {
                "http_proxy": self.proxy.http_proxy,
                "https_proxy": self.proxy.https_proxy,
                "no_proxy": self.proxy.no_proxy,
                "verify_ssl": self.proxy.verify_ssl,
                "ca_bundle": self.proxy.ca_bundle,
            },
        }
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"配置已保存到 {CONFIG_FILE}")
