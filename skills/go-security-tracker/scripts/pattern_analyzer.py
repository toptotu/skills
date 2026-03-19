"""
漏洞模式分析器 v2
- 三级分类策略：关键词评分 → CWE映射 → 新模式识别
- 新模式注册前与已有模式（含已发现）做相似度合并，避免碎片化
- 每条漏洞强制生成完整特征：漏洞特征 + 防御方案 + 代码修改对比
- 新模式也有完整的特征和代码示例（基于 CWE/描述/模板生成）
"""

import json
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

PATTERNS_CACHE = Path.home() / ".go-security-tracker" / "discovered_patterns.json"

# 新模式阈值：两级都未命中时才识别为新模式
NEW_PATTERN_THRESHOLD = 0.10
# 新模式合并阈值：关键词 Jaccard 相似度超过此值则合并
MERGE_SIMILARITY_THRESHOLD = 0.35

# ---------------------------------------------------------------------------
# 加权关键词（Top-3 归一化评分）
# ---------------------------------------------------------------------------

PATTERN_WEIGHTED_KEYWORDS: dict[str, dict[str, float]] = {
    "G-INJ": {
        "sql injection": 2, "command injection": 2, "template injection": 2,
        "ldap injection": 2, "code injection": 2, "os command": 2,
        "improper neutralization": 2, "special elements": 1.5,
        "neutralization of": 1.5, "output encoding": 1.5,
        "sanitize": 1, "sanitization": 1, "unsanitized": 1.5,
        "injection": 1.5, "sql": 1, "exec.command": 1.5, "os/exec": 1.5,
        "text/template": 1.5, "xss": 1.5, "cross-site scripting": 2,
        "ssti": 2, "log injection": 1.5, "format string": 1.5,
        "注入": 1.5, "命令执行": 2,
    },
    "G-AUTH": {
        "authentication bypass": 2, "authorization bypass": 2, "privilege escalation": 2,
        "unauthenticated": 2, "improper authentication": 2, "improper access control": 2,
        "unauthorized access": 2, "unauthorized": 1.5,
        "access control": 1.5, "missing authorization": 2, "missing authentication": 2,
        "incorrect authorization": 2, "rbac": 1.5, "jwt": 1.5, "token forgery": 2,
        "permissions on": 1.5, "insufficient permissions": 2, "insufficient restriction": 2,
        "improperly restricts": 1.5, "without authentication": 2, "without check": 1.5,
        "without auditing": 1.5, "missing check": 1.5, "missing permission": 2,
        "enumerate": 1.5, "spoofing": 1.5, "spoof": 1.5,
        "information disclosure": 1, "information exposure": 1.5, "credential leak": 2,
        "credentials": 1, "authorization": 1, "authentication": 1, "oidc": 1.5,
        "removed team": 1.5, "removed member": 1.5, "removed user": 1.5,
        "policy allows": 1.5, "policy enables": 1.5, "network policy": 1.5,
        "create-only policy": 2, "bypass": 1, "overwrite": 1,
        "coerced into leaking": 2, "leaking credentials": 2,
        "not bound to": 1.5, "output disclosure": 1.5,
        "cwe-284": 2, "cwe-862": 2, "cwe-863": 2, "cwe-200": 1.5, "cwe-287": 2,
        "认证绕过": 2, "越权": 2, "提权": 2, "权限不足": 2, "枚举": 1.5,
    },
    "G-DOS": {
        "denial of service": 2, "resource exhaustion": 2, "cpu exhaustion": 2,
        "memory exhaustion": 2, "infinite loop": 2, "goroutine leak": 2,
        "http/2 reset": 2, "rapid reset": 2, "regexdos": 2, "amplification": 1.5,
        "unbounded": 2, "unbounded allocation": 2, "unbounded memory": 2,
        "allocation of resources": 2, "resource without limits": 2, "without limits": 1.5,
        "allocation without": 1.5, "very long password": 1.5, "very long": 1,
        "crafted": 1, "malformed": 1.5, "specially crafted": 2, "flood": 1.5,
        "panic": 1, "rate limit": 1, "rate-limiting": 1,
        " dos ": 2, "vulnerable to dos": 2, "dos via": 2, "dos in": 1.5,
        "cwe-400": 2, "cwe-770": 2,
        "拒绝服务": 2, "内存耗尽": 2, "goroutine 泄漏": 2,
    },
    "G-MEM": {
        "buffer overflow": 2, "out of bounds": 2, "use after free": 2,
        "memory corruption": 2, "unsafe.pointer": 2, "heap overflow": 2,
        "stack overflow": 2, "nil pointer": 1.5, "nil dereference": 2,
        "unsafe": 1, "cgo": 1.5, "integer overflow": 2, "integer underflow": 2,
        "type confusion": 2, "memory leak": 1,
        "cwe-119": 2, "cwe-125": 2, "cwe-787": 2, "cwe-416": 2,
        "内存越界": 2, "内存损坏": 2,
    },
    "G-PROTO": {
        "protobuf": 1.5, "yaml": 1, "xml": 0.5,
        "deserialization": 2, "unmarshaling": 1.5, "parsing": 0.5,
        "billion laughs": 2, "zip bomb": 2, "message bomb": 2,
        "websocket": 1.5, "grpc": 1.5, "codec": 1,
        "protocol implementation": 2, "protocol error": 1.5,
        "message parsing": 1.5, "packet parsing": 1.5, "frame parsing": 1.5,
        "error in protocol": 2,
        "cwe-502": 2, "cwe-303": 1.5,
        "序列化": 1.5, "反序列化": 2, "解析": 0.5,
    },
    "G-CRYPTO": {
        "cryptographic": 1.5, "certificate": 1.5, "tls": 1.5, "ssl": 1.5,
        "insecureskipverify": 2, "weak randomness": 2, "math/rand": 2,
        "weak cipher": 2, "key generation": 1, "ecdsa": 1.5, "rsa": 1,
        "signature forgery": 2, "timing attack": 2, "side-channel": 2,
        "ciphertext forgery": 2, "forgery": 1.5, "sm9": 2,
        "infinity point": 2, "point at infinity": 2,
        "consistent error": 1.5, "timing side": 2, "observable difference": 1.5,
        "cwe-203": 2, "cwe-330": 2, "cwe-326": 2, "cwe-327": 2, "cwe-295": 2,
        "加密": 1, "证书绕过": 2, "密码学": 1.5,
    },
    "G-SSRF": {
        "server-side request forgery": 2, "ssrf": 2, "open redirect": 2,
        "unvalidated redirect": 2, "metadata service": 2, "169.254": 2,
        "internal network": 1.5, "http.client": 1, "url validation": 1.5,
        "dns rebinding": 2, "webhook": 1, "request forgery": 2,
        "cwe-918": 2, "cwe-601": 2,
        "服务端请求伪造": 2, "内网访问": 2,
    },
    "G-PATH": {
        "path traversal": 2, "directory traversal": 2, "zip slip": 2,
        "symlink": 1.5, "filepath.join": 1.5, "arbitrary file": 2,
        "file read": 1, "file write": 1, "../": 2, "dotdot": 2,
        "outside of": 1.5, "outside the": 1, "unpack target": 2,
        "chmod": 1.5, "placeholders in": 1.5, "plugin director": 1.5,
        "outside container": 2, "extract": 0.5, "archive": 0.5,
        "cwe-22": 2, "cwe-23": 2, "cwe-59": 2,
        "路径遍历": 2, "目录穿越": 2, "符号链接": 1.5, "任意文件": 2,
    },
    "G-RACE": {
        "race condition": 2, "data race": 2, "toctou": 2, "time-of-check": 2,
        "concurrent": 1, "mutex": 0.5, "map concurrent": 2, "locking": 1,
        "cwe-362": 2, "cwe-667": 2,
        "竞争条件": 2, "数据竞争": 2, "并发": 1,
    },
    "G-SUPPLY": {
        "supply chain": 2, "typosquatting": 2, "malicious package": 2,
        "module replacement": 2, "go.sum": 1.5, "dependency confusion": 2,
        "compromised dependency": 2, "untrusted source": 1.5,
        "cwe-1035": 2, "cwe-829": 2,
        "供应链": 2, "恶意依赖": 2,
    },
}

# ---------------------------------------------------------------------------
# CWE → 已知模式的直接映射（第二级分类）
# ---------------------------------------------------------------------------

CWE_TO_PATTERN: dict[str, str] = {
    # 注入
    "CWE-79":  "G-INJ",   "CWE-89":   "G-INJ",  "CWE-78":  "G-INJ",
    "CWE-94":  "G-INJ",   "CWE-116":  "G-INJ",  "CWE-138": "G-INJ",
    "CWE-74":  "G-INJ",   "CWE-77":   "G-INJ",
    # 认证/授权
    "CWE-287": "G-AUTH",  "CWE-284":  "G-AUTH", "CWE-285": "G-AUTH",
    "CWE-862": "G-AUTH",  "CWE-863":  "G-AUTH", "CWE-200": "G-AUTH",
    "CWE-201": "G-AUTH",  "CWE-209":  "G-AUTH", "CWE-306": "G-AUTH",
    "CWE-346": "G-AUTH",  "CWE-20":   "G-AUTH", "CWE-863": "G-AUTH",
    "CWE-1188":"G-AUTH",  "CWE-732":  "G-AUTH",
    # DoS
    "CWE-400": "G-DOS",   "CWE-770":  "G-DOS",  "CWE-835": "G-DOS",
    "CWE-834": "G-DOS",   "CWE-674":  "G-DOS",  "CWE-776": "G-DOS",
    # 内存
    "CWE-119": "G-MEM",   "CWE-125":  "G-MEM",  "CWE-787": "G-MEM",
    "CWE-416": "G-MEM",   "CWE-122":  "G-MEM",  "CWE-190": "G-MEM",
    "CWE-191": "G-MEM",   "CWE-476":  "G-MEM",
    # 协议/序列化
    "CWE-502": "G-PROTO", "CWE-303":  "G-PROTO","CWE-924": "G-PROTO",
    # 密码学
    "CWE-203": "G-CRYPTO","CWE-330":  "G-CRYPTO","CWE-326": "G-CRYPTO",
    "CWE-327": "G-CRYPTO","CWE-295":  "G-CRYPTO","CWE-338": "G-CRYPTO",
    # SSRF
    "CWE-918": "G-SSRF",  "CWE-601":  "G-SSRF",
    # 路径
    "CWE-22":  "G-PATH",  "CWE-23":   "G-PATH", "CWE-59":  "G-PATH",
    "CWE-73":  "G-PATH",  "CWE-434":  "G-PATH",
    # 竞争
    "CWE-362": "G-RACE",  "CWE-367":  "G-RACE", "CWE-667": "G-RACE",
    # 供应链
    "CWE-1035":"G-SUPPLY","CWE-829":  "G-SUPPLY",
    # 信息泄露 → 通常是 AUTH
    "CWE-372": "G-AUTH",  # (protocol state issues often relate to auth)
}

# 被识别为新模式但实际应映射回已知模式的词汇
_REMAP_TO_KNOWN: list[tuple[str, str]] = [
    # (关键词, 已知模式)
    ("websocket",          "G-PROTO"),
    ("grpc",               "G-PROTO"),
    ("protocol implementation", "G-PROTO"),
    ("error in protocol",  "G-PROTO"),
    ("insecure cors",      "G-AUTH"),
    ("cors",               "G-AUTH"),
    ("cross-origin",       "G-AUTH"),
    ("information disclosure", "G-AUTH"),
    ("information exposure", "G-AUTH"),
    ("improper neutralization", "G-INJ"),
    ("special elements",   "G-INJ"),
    ("unbounded allocation", "G-DOS"),
    ("allocation of resources", "G-DOS"),
    ("resource without limits", "G-DOS"),
    ("uncontrolled resource", "G-DOS"),
    ("vulnerable to dos", "G-DOS"),
    ("dos via",             "G-DOS"),
    ("dos in",              "G-DOS"),
    ("outside of unpack",  "G-PATH"),
    ("chmod of",           "G-PATH"),
    ("plugin director",    "G-PATH"),
    ("timing attack",      "G-CRYPTO"),
    ("side channel",       "G-CRYPTO"),
    ("side-channel",       "G-CRYPTO"),
    ("integer overflow",   "G-MEM"),
    ("integer underflow",  "G-MEM"),
    ("nil pointer",        "G-MEM"),
    ("type confusion",     "G-MEM"),
    ("open redirect",      "G-SSRF"),
    ("unvalidated redirect", "G-SSRF"),
    ("csrf",               "G-AUTH"),
    ("xss",                "G-INJ"),
    ("xxe",                "G-PROTO"),
    ("idor",               "G-AUTH"),
    ("session fixation",   "G-AUTH"),
    ("missing permission", "G-AUTH"),
    ("improper access",    "G-AUTH"),
    ("access control",     "G-AUTH"),
    ("network policy",     "G-AUTH"),
    ("log injection",      "G-INJ"),
    ("format string",      "G-INJ"),
    ("improperly sanitizes", "G-INJ"),
    ("credential leak",    "G-AUTH"),
    ("credential exposure","G-AUTH"),
    ("variable leak",      "G-AUTH"),
    ("env variable leak",  "G-AUTH"),
    ("environment variable leak", "G-AUTH"),
    ("secret leak",        "G-AUTH"),
    ("token leak",         "G-AUTH"),
    ("enumerate",          "G-AUTH"),
    ("removed team member", "G-AUTH"),
    ("data race",          "G-RACE"),
    ("race condition",     "G-RACE"),
    ("supply chain",       "G-SUPPLY"),
    ("malicious package",  "G-SUPPLY"),
]


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class PatternMatch:
    pattern_id:  str
    confidence:  float
    source:      str = "keyword"   # "keyword" | "cwe" | "remap" | "new"
    is_new:      bool = False


@dataclass
class VulnCharacteristics:
    pattern_id:   str
    pattern_name: str
    is_new_pattern: bool = False

    vuln_features:   list[str] = field(default_factory=list)
    before_code:     str = ""
    after_code:      str = ""
    diff_filename:   str = ""
    defense_points:  list[str] = field(default_factory=list)
    trigger_conditions: list[str] = field(default_factory=list)

    new_pattern_keywords:    list[str] = field(default_factory=list)
    new_pattern_description: str = ""
    characteristics_source:  str = "template"  # "diff" | "template" | "description"


@dataclass
class DiscoveredPattern:
    id:          str
    name_zh:     str
    name_en:     str
    description: str
    keywords:    list[str]
    first_seen:  str
    first_date:  str
    count:       int = 1
    examples:    list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 模式评分（三级分类）
# ---------------------------------------------------------------------------

def score_pattern(text: str, pattern_id: str) -> float:
    keywords = PATTERN_WEIGHTED_KEYWORDS.get(pattern_id, {})
    if not keywords:
        return 0.0
    text_lower = text.lower()
    hit_score  = sum(w for kw, w in keywords.items() if kw in text_lower)
    top3       = sorted(keywords.values(), reverse=True)[:3]
    max_score  = sum(top3)
    if max_score == 0:
        return 0.0
    return min(hit_score / max_score, 1.0)


def classify_with_confidence(advisory: dict) -> PatternMatch:
    """
    三级分类：
      1. 关键词加权评分（所有已知模式）
      2. CWE 直接映射（补充关键词未覆盖的情况）
      3. 重映射词汇检查（将常见新模式词汇归回已知类别）
    只有三级均未命中时才标记为新模式。
    """
    text = " ".join([
        advisory.get("title", ""),
        advisory.get("description", ""),
        " ".join(advisory.get("cwes", []) or []),
    ])
    text_lower = text.lower()

    # 级别 1：关键词评分
    scores = {pid: score_pattern(text, pid)
              for pid in PATTERN_WEIGHTED_KEYWORDS}
    best_id    = max(scores, key=lambda k: scores[k])
    best_score = scores[best_id]

    if best_score >= NEW_PATTERN_THRESHOLD:
        return PatternMatch(pattern_id=best_id, confidence=best_score, source="keyword")

    # 级别 2：CWE 映射
    for cwe in (advisory.get("cwes", []) or []):
        cwe_upper = cwe.upper()
        if cwe_upper in CWE_TO_PATTERN:
            return PatternMatch(
                pattern_id=CWE_TO_PATTERN[cwe_upper],
                confidence=0.5,
                source="cwe",
            )

    # 级别 3：重映射词汇检查
    for kw, target_pat in _REMAP_TO_KNOWN:
        if kw in text_lower:
            return PatternMatch(
                pattern_id=target_pat,
                confidence=0.3,
                source="remap",
            )

    # 全部未命中 → 候选新模式
    return PatternMatch(
        pattern_id="G-OTHER",
        confidence=best_score,
        source="new",
        is_new=True,
    )


# ---------------------------------------------------------------------------
# 新模式名称推断
# ---------------------------------------------------------------------------

_FEATURE_VOCAB: list[tuple[str, str, str]] = [
    ("cache poisoning",     "缓存投毒",         "Cache Poisoning"),
    ("env variable",        "环境变量注入",      "Environment Variable Injection"),
    ("default configuration","不安全默认配置",  "Insecure Default Configuration"),
    ("state handling",      "状态管理缺陷",      "Incorrect State Handling"),
    ("state machine",       "状态机漏洞",        "State Machine Vulnerability"),
    ("evm",                 "EVM 执行漏洞",       "EVM Execution Flaw"),
    ("blockchain",          "区块链共识漏洞",    "Blockchain Consensus Flaw"),
    ("slashing evasion",    "共识惩罚规避",      "Consensus Slashing Evasion"),
    ("smart contract",      "智能合约漏洞",      "Smart Contract Vulnerability"),
    ("delegation",          "代理/委托安全",     "Delegation Security Flaw"),
    ("re-delegation",       "重委托攻击",        "Re-delegation Attack"),
    ("amf",                 "AMF 协议漏洞",       "AMF Protocol Vulnerability"),
    ("5g",                  "5G 协议漏洞",        "5G Protocol Vulnerability"),
    ("nrf",                 "网络功能注册漏洞",  "Network Function Registry Flaw"),
    ("supi",                "SUPI 处理漏洞",      "SUPI Handling Flaw"),
    ("metadata parser",     "元数据解析漏洞",    "Metadata Parser Vulnerability"),
    ("sparse map",          "稀疏映射解析漏洞",  "Sparse Map Parsing Flaw"),
    ("burn-on-read",        "阅后即焚逻辑缺陷",  "Burn-on-Read Logic Flaw"),
    ("permalink",           "永久链接伪造",      "Permalink Spoofing"),
    ("compliance export",   "合规导出审计缺失",  "Compliance Export Audit Gap"),
    ("tkey",                "硬件密钥协议漏洞",  "Hardware Key Protocol Flaw"),
    ("upstream id",         "上游ID信任漏洞",    "Upstream ID Trust Flaw"),
    ("network function",    "网络功能安全缺陷",  "Network Function Security Flaw"),
    ("e2e metadata",        "端到端元数据解析",  "E2E Metadata Parsing Flaw"),
]


def _infer_new_pattern_name(advisory: dict) -> tuple[str, str, list[str]]:
    text = " ".join([advisory.get("title", ""), advisory.get("description", "")]).lower()
    for kw, zh, en in _FEATURE_VOCAB:
        if kw in text:
            words = re.findall(r'\b[a-z][a-z0-9\-/]{2,}\b', text)
            stop = {"the","and","for","that","this","with","from","are","can",
                    "use","using","used","when","which","have","been","not","but",
                    "may","allow","allows","via","into","during","within","without"}
            keywords = list(dict.fromkeys(
                w for w in words if len(w) > 3 and w not in stop
            ))[:8]
            return zh, en, [kw] + keywords

    title = advisory.get("title", "Unknown")
    title_clean = re.sub(r'\([^)]*\)', '', title).strip()
    parts = [w for w in title_clean.split() if len(w) > 2][:5]
    name_en = " ".join(parts) or "Unknown Pattern"
    words = re.findall(r'\b[a-z][a-z0-9\-]{2,}\b', text)
    keywords = list(dict.fromkeys(w for w in words if len(w) > 3))[:6]
    return name_en, name_en, keywords


# ---------------------------------------------------------------------------
# 新模式合并（Jaccard 相似度）
# ---------------------------------------------------------------------------

def _jaccard(set_a: set, set_b: set) -> float:
    if not set_a and not set_b:
        return 0.0
    return len(set_a & set_b) / len(set_a | set_b)


def _load_discovered_patterns() -> dict[str, DiscoveredPattern]:
    if not PATTERNS_CACHE.exists():
        return {}
    try:
        with open(PATTERNS_CACHE, encoding="utf-8") as f:
            raw = json.load(f)
        return {k: DiscoveredPattern(**v) for k, v in raw.items()}
    except Exception:
        return {}


def _save_discovered_patterns(patterns: dict[str, DiscoveredPattern]) -> None:
    PATTERNS_CACHE.parent.mkdir(parents=True, exist_ok=True)
    with open(PATTERNS_CACHE, "w", encoding="utf-8") as f:
        json.dump({k: asdict(v) for k, v in patterns.items()},
                  f, indent=2, ensure_ascii=False, default=str)


def _next_pattern_id(existing: dict) -> str:
    nums = [int(m.group(1)) for k in existing
            if (m := re.match(r'G-NEW-(\d+)', k))]
    return f"G-NEW-{(max(nums) + 1 if nums else 1):03d}"


def register_new_pattern(advisory: dict, name_zh: str, name_en: str,
                         keywords: list[str], description: str, date_str: str) -> str:
    """
    注册新模式前先检查：
    1. 与已有新模式关键词 Jaccard 相似度 >= MERGE_SIMILARITY_THRESHOLD → 合并
    2. 与已有新模式标题语义相似（标题词重叠 >= 2 个有意义词）→ 合并
    3. 均不满足 → 创建新条目
    """
    patterns = _load_discovered_patterns()
    vid = advisory.get("id") or advisory.get("cve_id") or ""
    kw_set = set(keywords)

    # 检查关键词重叠
    for pid, p in patterns.items():
        p_set = set(p.keywords)
        if _jaccard(kw_set, p_set) >= MERGE_SIMILARITY_THRESHOLD:
            p.count += 1
            if vid and vid not in p.examples:
                p.examples.append(vid)
            _save_discovered_patterns(patterns)
            return pid

    # 检查标题词重叠（过滤停用词后）
    _stop = {"the","has","via","in","of","to","a","an","for","with","from","is","are","can","by","at","on"}
    title_words = set(w.lower() for w in re.findall(r'\b\w+\b', name_en) if w.lower() not in _stop and len(w) > 2)
    for pid, p in patterns.items():
        p_title_words = set(w.lower() for w in re.findall(r'\b\w+\b', p.name_en) if w.lower() not in _stop and len(w) > 2)
        if len(title_words & p_title_words) >= 2:
            p.count += 1
            if vid and vid not in p.examples:
                p.examples.append(vid)
            _save_discovered_patterns(patterns)
            return pid

    # 新建条目
    new_id = _next_pattern_id(patterns)
    patterns[new_id] = DiscoveredPattern(
        id=new_id, name_zh=name_zh, name_en=name_en,
        description=description, keywords=keywords,
        first_seen=vid, first_date=date_str,
        count=1, examples=[vid] if vid else [],
    )
    _save_discovered_patterns(patterns)
    return new_id


def get_discovered_patterns() -> dict[str, DiscoveredPattern]:
    return _load_discovered_patterns()


# ---------------------------------------------------------------------------
# 漏洞特征模板（已知模式）
# ---------------------------------------------------------------------------

PATTERN_VULN_FEATURES: dict[str, list[str]] = {
    "G-INJ": [
        "用户输入未经过滤直接拼接到查询/命令字符串",
        "使用 text/template 而非 html/template 渲染用户可控数据",
        "exec.Command 以字符串形式传递用户输入（触发 shell 解析）",
        "数据库查询通过 fmt.Sprintf 或字符串加法动态构造，而非参数化",
    ],
    "G-AUTH": [
        "认证/权限校验逻辑存在可绕过的条件分支或缺失",
        "权限检查在请求处理链路中位置错误或未覆盖所有入口",
        "JWT 未强制校验签名算法类型，允许 alg:none 绕过签名验证",
        "移除/禁用状态的用户或成员仍可访问受限资源（缺少状态重验证）",
        "接口未校验调用方是否拥有目标资源的访问权限",
    ],
    "G-DOS": [
        "处理用户可控输入时对大小/数量无上限限制，导致资源耗尽",
        "goroutine 在特定条件下（channel 阻塞/context 未传播）无法退出",
        "HTTP/2 流或请求帧处理未设置并发数量上限",
        "正则表达式存在指数级回溯路径，输入特殊字符串触发 CPU 100%",
        "解析特殊格式输入时触发无限循环或无界内存分配",
    ],
    "G-MEM": [
        "unsafe.Pointer 转换前未做边界验证",
        "切片索引操作缺乏 len/cap 长度检查",
        "cgo 接口未对来自 C 侧的数据大小和指针有效性进行校验",
        "整数运算（加法/乘法）未检查溢出，影响后续内存分配大小",
    ],
    "G-PROTO": [
        '反序列化时未限制最大消息体积，允许"解析炸弹"消耗内存',
        "YAML/JSON 解析器接受包含任意类型的用户输入（如 !!python/object）",
        "Protobuf 嵌套消息深度无上限，可触发栈溢出",
        "协议实现中的状态机转换未校验前置条件，导致非预期状态切换",
    ],
    "G-CRYPTO": [
        "使用 math/rand 而非 crypto/rand 生成安全相关的随机数或 token",
        "TLS 配置中设置 InsecureSkipVerify: true，跳过证书链验证",
        "不同输入时的错误响应存在可观测差异，泄露侧信道信息",
        "密码学算法的输入参数（如曲线上的点、密钥）来自不可信来源，未做合法性校验",
    ],
    "G-SSRF": [
        "http.Client 直接使用用户提供的 URL，未过滤私有 IP 段",
        "重定向跟随策略未限制目标地址范围，可跳转到内网或云元数据接口",
        "Webhook/import/fetch 功能接受任意 URL，可被用于内网探测",
    ],
    "G-PATH": [
        "filepath.Join 未验证用户输入是否包含 '../' 序列，导致路径逃逸",
        "解压 tar/zip 归档时未校验每个 entry 的路径是否在目标目录内",
        "文件操作目标路径未通过 filepath.Rel 确认在允许的根目录范围内",
        "文件系统对象权限在宿主机上被修改（符号链接或 chmod 操作逃逸沙箱）",
    ],
    "G-RACE": [
        "多 goroutine 并发读写同一 map 未加锁，触发 concurrent map writes panic",
        "check-then-act 操作（如文件存在检查后写入）之间存在竞争窗口（TOCTOU）",
        "全局共享变量在并发场景下缺乏原子操作或互斥锁保护",
    ],
    "G-SUPPLY": [
        "第三方依赖包路径可被仿冒（typosquatting），指向恶意包",
        "go.mod 未锁定精确版本，依赖解析可能拉取恶意更新",
        "构建流程从未经完整性验证的来源下载依赖",
    ],
}

# 防御方案模板
PATTERN_DEFENSE_POINTS: dict[str, list[str]] = {
    "G-INJ": [
        "使用参数化查询（database/sql 的 `?` 占位符或 ORM），禁止字符串拼接 SQL",
        "命令执行传入参数数组：`exec.Command(\"cmd\", arg1, arg2)` 而非 shell 字符串",
        "输出 HTML 时使用 `html/template`，利用自动转义防止 XSS",
        "对所有外部输入实施严格白名单验证，不信任任何来自网络的字段",
    ],
    "G-AUTH": [
        "在中间件层统一处理认证鉴权，不在 handler 内分散进行权限判断",
        "JWT 解析时强制校验 token.Method 类型：`if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return error }`",
        "使用 `crypto/subtle.ConstantTimeCompare` 比较 token/密码，消除时序侧信道",
        "对已删除/禁用的用户每次请求都重新验证其状态，不依赖 session 缓存",
    ],
    "G-DOS": [
        "所有 HTTP handler 包装 `http.TimeoutHandler`，设置合理超时时间",
        "使用 `http.MaxBytesReader(w, r.Body, limit)` 限制请求体大小",
        "goroutine 启动时传入 context，确保在 context 取消时能退出",
        "HTTP/2 Server 配置 `MaxConcurrentStreams: 250` 限制并发流",
        "解析外部数据前验证大小，拒绝超过阈值的输入",
    ],
    "G-MEM": [
        "unsafe 操作前做完整边界检查：`if len(b) < n { return error }`",
        "使用 `encoding/binary` 等标准库替代 `unsafe.Pointer` 进行内存读写",
        "CI 中加入 `-race` 标志：`go test -race ./...`",
        "对整数运算使用 `math/bits.Add64` 等可检测溢出的函数",
    ],
    "G-PROTO": [
        "设置 `grpc.MaxRecvMsgSize` / `grpc.MaxSendMsgSize` 限制消息大小",
        "YAML 使用 `gopkg.in/yaml.v3` 并调用 `decoder.KnownFields(true)` 拒绝未知字段",
        "反序列化前验证数据总大小，使用 `io.LimitReader` 限制读取量",
        "协议状态机实现中对每个状态转换校验前置条件和输入合法性",
    ],
    "G-CRYPTO": [
        "所有随机数生成使用 `crypto/rand`，禁止 `math/rand` 用于安全场景",
        "TLS 配置：`MinVersion: tls.VersionTLS12`，移除弱 cipher suite",
        "对于签名/MAC 验证，返回统一的错误信息，避免可观测差异",
        "接收密码学输入（如曲线点、公钥参数）前做格式和合法性验证",
    ],
    "G-SSRF": [
        "自定义 http.Transport.DialContext，过滤私有 IP 段（10.x, 172.16.x, 192.168.x, 169.254.x）",
        "设置 `CheckRedirect: func() error { return http.ErrUseLastResponse }` 禁止自动跟随重定向",
        "对 URL 实施白名单验证：只允许特定域名/协议，拒绝 IP 直连",
    ],
    "G-PATH": [
        "验证路径在允许目录内：`rel, _ := filepath.Rel(base, joined); if strings.HasPrefix(rel, \"..\") { error }`",
        "解压 archive 时对每个 entry 调用 `filepath.Clean` 后检查是否包含 '..'",
        "使用 Go 1.24+ 的 `os.OpenRoot` 创建沙箱文件句柄，防止路径逃逸",
        "容器运行时操作文件系统时在 chroot 环境内执行，避免宿主机路径暴露",
    ],
    "G-RACE": [
        "共享 map 访问使用 `sync.RWMutex` 保护，或改用 `sync.Map`",
        "`sync/atomic` 原子操作替代简单整数的并发读写",
        "CI 流水线加入 `go test -race ./...` 强制检测数据竞争",
    ],
    "G-SUPPLY": [
        "启用 GONOSUMCHECK=off，所有依赖经 go.sum 校验",
        "定期运行 `govulncheck ./...` 检查已知漏洞依赖",
        "使用私有 GOPROXY 镜像 + 依赖审计，防止 typosquatting",
    ],
}

# 代码对比示例（每个已知模式必须有）
PATTERN_CODE_EXAMPLES: dict[str, tuple[str, str]] = {
    "G-INJ": (
        # before
        '// ❌ 字符串拼接构造 SQL，触发注入\nquery := "SELECT * FROM users WHERE name = \'" + userInput + "\'"\ndb.Query(query)\n\n// ❌ 命令注入\ncmd := exec.Command("sh", "-c", "git clone " + userURL)',
        # after
        '// ✅ 参数化查询\nquery := "SELECT * FROM users WHERE name = ?"\ndb.Query(query, userInput)\n\n// ✅ 参数数组形式，避免 shell 解析\ncmd := exec.Command("git", "clone", "--", validatedURL)',
    ),
    "G-AUTH": (
        '// ❌ JWT 未校验算法类型，alg:none 可绕过\ntoken, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {\n    return secretKey, nil  // 任何算法都接受！\n})',
        '// ✅ 强制验证算法\ntoken, _ := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {\n    if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {\n        return nil, fmt.Errorf("unexpected alg: %v", t.Header["alg"])\n    }\n    return secretKey, nil\n})',
    ),
    "G-DOS": (
        '// ❌ 无大小限制，恶意请求可耗尽内存\nbody, _ := io.ReadAll(r.Body)\n\n// ❌ 无限制的 goroutine 启动\nfor _, req := range requests {\n    go process(req)  // goroutine 泄漏风险\n}',
        '// ✅ 限制请求体大小\nr.Body = http.MaxBytesReader(w, r.Body, 10<<20) // 10MB\nbody, err := io.ReadAll(r.Body)\n\n// ✅ Worker pool 控制并发数\nsem := make(chan struct{}, 100)\nfor _, req := range requests {\n    sem <- struct{}{}\n    go func(r Request) {\n        defer func() { <-sem }()\n        process(ctx, r)\n    }(req)\n}',
    ),
    "G-MEM": (
        '// ❌ unsafe.Pointer 未检查边界\nfunc readInt64(b []byte) int64 {\n    return *(*int64)(unsafe.Pointer(&b[0]))  // 若 len(b)<8 则越界！\n}',
        '// ✅ 使用标准库，显式边界检查\nfunc readInt64(b []byte) (int64, error) {\n    if len(b) < 8 {\n        return 0, fmt.Errorf("buffer too short: %d < 8", len(b))\n    }\n    return int64(binary.LittleEndian.Uint64(b)), nil\n}',
    ),
    "G-PROTO": (
        '// ❌ 无限制反序列化，允许"解析炸弹"\nvar msg proto.Message\nproto.Unmarshal(untrustedData, msg)  // 无大小检查\n\n// ❌ gRPC 服务端无消息大小限制\ns := grpc.NewServer()  // 默认 4MB，但生产建议显式设置',
        '// ✅ 先检查大小\nif len(untrustedData) > maxMsgSize {\n    return errors.New("message too large")\n}\nproto.Unmarshal(untrustedData, msg)\n\n// ✅ 显式限制 gRPC 消息大小\ns := grpc.NewServer(\n    grpc.MaxRecvMsgSize(4 * 1024 * 1024),  // 4MB\n    grpc.MaxSendMsgSize(4 * 1024 * 1024),\n)',
    ),
    "G-CRYPTO": (
        '// ❌ math/rand 生成 token，可预测\ntoken := fmt.Sprintf("%d", rand.Int63())\n\n// ❌ 跳过 TLS 证书验证\ntlsConfig := &tls.Config{InsecureSkipVerify: true}',
        '// ✅ crypto/rand 生成不可预测 token\nb := make([]byte, 32)\ncrypto_rand.Read(b)\ntoken := hex.EncodeToString(b)\n\n// ✅ 严格 TLS 配置\ntlsConfig := &tls.Config{\n    MinVersion: tls.VersionTLS12,\n    // InsecureSkipVerify 不设置（默认 false）\n}',
    ),
    "G-SSRF": (
        '// ❌ 直接使用用户提供的 URL，可访问内网 169.254.169.254\nresp, _ := http.Get(req.FormValue("url"))',
        '// ✅ 自定义 Transport 过滤内网地址\nclient := &http.Client{\n    Transport: &http.Transport{\n        DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {\n            host, _, _ := net.SplitHostPort(addr)\n            if isPrivateIP(net.ParseIP(host)) {\n                return nil, fmt.Errorf("SSRF: blocked private IP %s", host)\n            }\n            return net.Dial(network, addr)\n        },\n    },\n    CheckRedirect: func(r *http.Request, via []*http.Request) error {\n        return http.ErrUseLastResponse  // 禁止自动重定向\n    },\n}',
    ),
    "G-PATH": (
        '// ❌ filepath.Join 可被绝对路径覆盖\nfullPath := filepath.Join(baseDir, userInput)\nhttp.ServeFile(w, r, fullPath)  // 用户输入 "/etc/passwd" → 泄露！',
        '// ✅ 验证路径在 base 目录内\nclean := filepath.Clean(userInput)\nfull := filepath.Join(baseDir, clean)\nrel, err := filepath.Rel(baseDir, full)\nif err != nil || strings.HasPrefix(rel, "..") {\n    http.Error(w, "forbidden", http.StatusForbidden)\n    return\n}\nhttp.ServeFile(w, r, full)',
    ),
    "G-RACE": (
        '// ❌ 并发读写 map，触发 panic\nvar cache = map[string]string{}\nfunc setCache(k, v string) {\n    cache[k] = v  // concurrent map writes → panic!\n}',
        '// ✅ 方式1：sync.RWMutex\nvar (\n    cache   = map[string]string{}\n    cacheMu sync.RWMutex\n)\nfunc setCache(k, v string) {\n    cacheMu.Lock()\n    defer cacheMu.Unlock()\n    cache[k] = v\n}\n\n// ✅ 方式2：sync.Map\nvar safeCache sync.Map\nsafeCache.Store(k, v)',
    ),
    "G-SUPPLY": (
        '# ❌ go.mod 中使用可变标签或 replace 指向本地路径\nrequire github.com/legit/pkg latest  # 可被恶意更新替换\nreplace github.com/legit/pkg => ../malicious-pkg',
        '# ✅ 锁定精确版本，启用 go.sum 校验\nrequire github.com/legit/pkg v1.2.3  # 固定版本\n# 运行 govulncheck 扫描\ngo install golang.org/x/vuln/cmd/govulncheck@latest\ngovulncheck ./...',
    ),
}


# ---------------------------------------------------------------------------
# 特征提取
# ---------------------------------------------------------------------------

def _extract_impact_sentences(text: str, max_count: int = 2) -> list[str]:
    """从描述文本中提取影响语句（包含"允许"/"导致"等词的句子）。"""
    if not text:
        return []
    sentences = re.split(r'[.!?\n]', text)
    kws = ["allow", "can", "enables", "expose", "lead to", "result in",
           "bypass", "unauthorized", "without authentication", "arbitrary",
           "execute", "read", "write", "delete", "escalate", "enumerate",
           "leak", "disclose", "pivot", "attacker", "malicious", "exploit"]
    results = []
    for sent in sentences[:10]:
        sent = sent.strip()
        if 20 < len(sent) < 250 and any(kw in sent.lower() for kw in kws):
            results.append(sent)
            if len(results) >= max_count:
                break
    return results


def _extract_trigger_conditions(advisory: dict) -> list[str]:
    conditions = []
    text = (advisory.get("description", "") or "").lower()
    if any(t in text for t in ("unauthenticated", "no authentication", "without credentials")):
        conditions.append("无需认证即可触发（匿名远程攻击者）")
    if any(t in text for t in ("remote", "network", "http", "api")):
        conditions.append("可通过网络远程触发")
    if "local" in text and "remote" not in text:
        conditions.append("需要本地访问权限")
    if any(t in text for t in ("authenticated user", "logged-in", "valid user")):
        conditions.append("需要普通用户认证凭证")
    if any(t in text for t in ("admin", "privileged", "root")):
        conditions.append("需要管理员或特权账户")
    if any(t in text for t in ("crafted", "malicious", "specially")):
        conditions.append("需要构造特殊格式的输入数据")
    return conditions[:3] if conditions else ["详见漏洞描述"]


def _generate_features_for_new_pattern(advisory: dict, dp) -> list[str]:
    """为新发现模式生成漏洞特征（从描述提取 + 通用模板）。"""
    features = []

    # 从描述提取关键影响句子
    desc = advisory.get("description", "") or ""
    title = advisory.get("title", "") or ""
    impact_sents = _extract_impact_sentences(desc)
    features.extend(impact_sents)

    # 从标题推断特征
    if title:
        title_lower = title.lower()
        if "fails to" in title_lower or "improperly" in title_lower:
            features.append(f"相关组件在特定场景下未能正确执行安全校验：{title}")
        elif "allows" in title_lower:
            features.append(f"攻击者可利用此漏洞：{title}")
        elif "incorrect" in title_lower or "invalid" in title_lower:
            features.append(f"安全相关逻辑存在错误实现：{title}")

    # 补充通用特征（若不足 2 条）
    if len(features) < 2 and dp and dp.keywords:
        features.append(f"关键特征词：{', '.join(dp.keywords[:4])}")
    if len(features) < 1:
        features.append(f"漏洞详情：{title or '见 advisory 描述'}")

    return features[:4]


def _generate_defense_for_new_pattern(advisory: dict) -> list[str]:
    """为新发现模式生成防御方案（从 resolution + CWE + 通用建议）。"""
    defense = []

    # 使用 resolution 字段
    raw_resolution = (advisory.get("_raw", {}) or {}).get("resolution", "")
    if not raw_resolution:
        # Try from nested affected
        for a in advisory.get("affected", []):
            r = a.get("resolution", "")
            if r:
                raw_resolution = r
                break

    if raw_resolution and len(raw_resolution) > 20:
        defense.append(f"官方建议：{raw_resolution[:200]}")

    # 基于 CWE 的防御
    cwe_defense = {
        "CWE-284": "实施严格的访问控制列表（ACL），每次请求都验证调用方权限",
        "CWE-400": "对所有外部输入设置大小和数量上限，使用 io.LimitReader 限制读取量",
        "CWE-770": "使用 http.MaxBytesReader 或自定义 validator 限制资源分配",
        "CWE-362": "使用 sync.Mutex/sync.RWMutex 保护共享状态，CI 中加入 -race 标志",
        "CWE-20":  "对所有外部输入实施严格类型和范围验证，采用白名单策略",
        "CWE-203": "统一错误响应，消除基于错误内容的信息泄露",
        "CWE-1188":"禁止在生产部署中使用默认配置，强制要求显式安全配置",
        "CWE-346": "验证所有请求的来源（Origin/Referer），实施 CORS 白名单",
    }
    for cwe in (advisory.get("cwes", []) or []):
        if cwe in cwe_defense and len(defense) < 3:
            defense.append(cwe_defense[cwe])

    # 补充通用建议
    if len(defense) < 2:
        defense.append("升级到官方已发布的修复版本，参见 advisory 中的修复版本信息")
    if len(defense) < 3:
        defense.append("在 CI/CD 流水线中集成 govulncheck 和 gosec 进行持续安全扫描")
    if len(defense) < 4:
        defense.append("参考 references/go_vuln_patterns.md 中对应漏洞类型的防御方案")

    return defense[:4]


def _generate_code_example_for_new_pattern(advisory: dict, dp) -> tuple[str, str]:
    """
    为新模式生成 before/after 代码对比。
    优先从 advisory description 中提取代码块，否则生成通用示例。
    """
    desc = advisory.get("description", "") or ""
    cwes = advisory.get("cwes", []) or []

    # 尝试从描述中提取代码块（Markdown 格式）
    code_blocks = re.findall(r'```(?:go|golang)?\n(.*?)```', desc, re.DOTALL)
    if len(code_blocks) >= 2:
        return code_blocks[0][:400], code_blocks[1][:400]
    if len(code_blocks) == 1:
        return code_blocks[0][:400], "// 参见官方 advisory 中的修复代码"

    # 基于 CWE 提供通用代码示例
    cwe_examples = {
        "CWE-284": (
            '// ❌ 未检查调用方是否拥有目标资源权限\nfunc getResource(ctx context.Context, userID, resourceID string) {\n    // 直接查询，无权限验证\n    return db.GetResource(resourceID)\n}',
            '// ✅ 先验证权限，再执行操作\nfunc getResource(ctx context.Context, userID, resourceID string) error {\n    if !hasPermission(ctx, userID, resourceID, "read") {\n        return errors.New("forbidden: insufficient permissions")\n    }\n    return db.GetResource(resourceID)\n}',
        ),
        "CWE-400": (
            '// ❌ 无限制读取，资源耗尽\ndata, err := io.ReadAll(reader)\nfor _, item := range items {  // 无数量上限\n    go process(item)\n}',
            '// ✅ 限制大小和并发数\ndata, err := io.ReadAll(io.LimitReader(reader, maxSize))\nsem := make(chan struct{}, maxConcurrency)\nfor _, item := range items {\n    sem <- struct{}{}\n    go func(i Item) { defer func() { <-sem }(); process(i) }(item)\n}',
        ),
        "CWE-20": (
            '// ❌ 直接使用未验证的用户输入\nfunc handler(r *http.Request) {\n    id := r.URL.Query().Get("id")\n    result := db.Query("SELECT * FROM t WHERE id=" + id)\n}',
            '// ✅ 验证输入类型和范围\nfunc handler(r *http.Request) error {\n    idStr := r.URL.Query().Get("id")\n    id, err := strconv.ParseInt(idStr, 10, 64)\n    if err != nil || id <= 0 {\n        return errors.New("invalid id parameter")\n    }\n    result, err := db.QueryRow("SELECT * FROM t WHERE id=?", id)\n    return err\n}',
        ),
    }

    for cwe in cwes:
        if cwe in cwe_examples:
            return cwe_examples[cwe]

    # 最后的通用示例
    title = advisory.get("title", "本漏洞") or "本漏洞"
    return (
        f'// ❌ 存在安全缺陷的代码模式\n// 漏洞: {title[:60]}\n// 原因: 缺少必要的安全检查或验证逻辑',
        f'// ✅ 修复后的代码模式\n// 修复: {title[:60]}\n// 升级到官方修复版本，参见 advisory 中的 fixed_version\n// 并审查相关调用路径，补充对应的安全校验',
    )


def _pattern_display_name(pattern_id: str) -> str:
    names = {
        "G-INJ":    "注入类漏洞",   "G-AUTH":   "认证/授权绕过",
        "G-DOS":    "拒绝服务（DoS）","G-MEM":   "内存安全",
        "G-PROTO":  "协议/序列化漏洞","G-CRYPTO": "密码学问题",
        "G-SSRF":   "服务端请求伪造","G-PATH":   "路径遍历",
        "G-RACE":   "竞争条件",      "G-SUPPLY": "供应链安全",
        "G-OTHER":  "其他/未分类",
    }
    if pattern_id in names:
        return names[pattern_id]
    dp = get_discovered_patterns().get(pattern_id)
    return dp.name_zh if dp else pattern_id


# ---------------------------------------------------------------------------
# 完整特征提取（每条漏洞必须有）
# ---------------------------------------------------------------------------

def extract_characteristics_from_diff(
    advisory: dict,
    patch_info,     # PatchInfo | None
    pattern_id: str,
) -> VulnCharacteristics:
    """
    为每条 advisory 生成完整的结构化特征。
    严格保证：vuln_features、defense_points、before_code、after_code 均非空。
    """
    is_new    = pattern_id.startswith("G-NEW-")
    pat_name  = _pattern_display_name(pattern_id)
    dp        = get_discovered_patterns().get(pattern_id) if is_new else None
    char_src  = "template"

    # ── 漏洞特征 ──────────────────────────────────────────────
    vuln_features: list[str] = []

    # 1. 从模式模板取前2条
    vuln_features.extend(PATTERN_VULN_FEATURES.get(pattern_id, [])[:2])

    # 2. 从描述提取影响句子
    desc_features = _extract_impact_sentences(advisory.get("description", ""), max_count=2)
    for f in desc_features:
        if f not in vuln_features:
            vuln_features.append(f)

    # 3. 新模式补充
    if is_new and len(vuln_features) < 2:
        vuln_features.extend(_generate_features_for_new_pattern(advisory, dp))

    # 4. 确保至少2条（fallback 到剩余模板）
    if len(vuln_features) < 2:
        remaining = PATTERN_VULN_FEATURES.get(pattern_id, [])[2:]
        vuln_features.extend(remaining[:2 - len(vuln_features)])
    if len(vuln_features) < 1:
        vuln_features.append(advisory.get("title", "见漏洞描述") or "见漏洞描述")

    # ── 触发条件 ──────────────────────────────────────────────
    trigger_conditions = _extract_trigger_conditions(advisory)

    # ── 防御方案 ──────────────────────────────────────────────
    defense_points: list[str] = list(PATTERN_DEFENSE_POINTS.get(pattern_id, [])[:3])
    if len(defense_points) < 2:
        # 新模式或模板不足时从描述生成
        extra = _generate_defense_for_new_pattern(advisory)
        for d in extra:
            if d not in defense_points:
                defense_points.append(d)
    # 最终保证至少2条
    if len(defense_points) < 2:
        defense_points.append("升级到官方修复版本，参见 advisory 中的修复信息")
    if len(defense_points) < 3:
        defense_points.append("在 CI/CD 中集成 govulncheck ./... 进行持续扫描")

    # ── 代码对比 ──────────────────────────────────────────────
    before_code = after_code = ""
    diff_filename = ""

    # 优先：真实代码 diff
    if patch_info and getattr(patch_info, "go_diffs", None):
        diffs = patch_info.go_diffs
        candidates = [d for d in diffs if not d.filename.endswith("_test.go")]
        best = max(candidates or diffs,
                   key=lambda d: len(d.before_lines) + len(d.after_lines),
                   default=None)
        if best and (best.before_lines or best.after_lines):
            before_code = _fmt_code(best.before_lines, 15)
            after_code  = _fmt_code(best.after_lines,  15)
            diff_filename = best.filename
            char_src = "diff"

    # 次优：已知模式的代码模板
    if not before_code and pattern_id in PATTERN_CODE_EXAMPLES:
        before_code, after_code = PATTERN_CODE_EXAMPLES[pattern_id]
        char_src = "template"

    # 最后：新模式自动生成
    if not before_code:
        before_code, after_code = _generate_code_example_for_new_pattern(advisory, dp)
        char_src = "description"

    return VulnCharacteristics(
        pattern_id=pattern_id,
        pattern_name=pat_name,
        is_new_pattern=is_new,
        vuln_features=vuln_features[:4],
        before_code=before_code,
        after_code=after_code,
        diff_filename=diff_filename,
        defense_points=defense_points[:4],
        trigger_conditions=trigger_conditions,
        new_pattern_keywords=dp.keywords if dp else [],
        new_pattern_description=dp.description if dp else "",
        characteristics_source=char_src,
    )


def _fmt_code(lines: list[str], max_lines: int) -> str:
    if not lines:
        return ""
    trimmed = lines[:max_lines]
    code = "\n".join(trimmed)
    if len(lines) > max_lines:
        code += f"\n// ... 省略 {len(lines) - max_lines} 行"
    return code


# ---------------------------------------------------------------------------
# 批量分析
# ---------------------------------------------------------------------------

def analyze_all(advisories: list[dict], patches: dict, date_str: str) -> list[dict]:
    """
    对所有 advisory 进行三级分类 + 完整特征提取。
    每条 advisory 新增字段：
      category, category_confidence, category_source,
      is_new_pattern, characteristics
    """
    for adv in advisories:
        match = classify_with_confidence(adv)
        vid = adv.get("id") or adv.get("cve_id") or adv.get("ghsa_id") or ""

        if match.is_new:
            name_zh, name_en, keywords = _infer_new_pattern_name(adv)
            desc = (adv.get("description") or "")[:200]
            pid = register_new_pattern(adv, name_zh, name_en, keywords, desc, date_str)
            match.pattern_id = pid

        adv["category"]            = match.pattern_id
        adv["category_confidence"] = round(match.confidence, 3)
        adv["category_source"]     = match.source
        adv["is_new_pattern"]      = match.is_new

        patch_info = patches.get(vid) if patches else None
        char = extract_characteristics_from_diff(adv, patch_info, match.pattern_id)
        adv["characteristics"] = asdict(char)

    return advisories
