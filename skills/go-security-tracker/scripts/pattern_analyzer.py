"""
漏洞模式分析器
- 对每条漏洞计算与 10 个已知模式的匹配得分（TF-IDF 风格的加权关键词匹配）
- 当最高匹配分 < 阈值时，自动识别新模式特征并分配 G-NEW-XXX 编号
- 将新发现的模式持久化到 ~/.go-security-tracker/discovered_patterns.json
- 从代码 diff 中提取"漏洞特征"和"防御特征"
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

# 每个已知模式的关键词权重表 {keyword: weight}
# 权重 2 = 高辨别力，权重 1 = 普通，0.5 = 弱信号
PATTERN_WEIGHTED_KEYWORDS: dict[str, dict[str, float]] = {
    "G-INJ": {
        "sql injection": 2, "command injection": 2, "template injection": 2,
        "ldap injection": 2, "code injection": 2, "script injection": 2,
        "injection": 1.5, "sql": 1, "exec.command": 1.5, "os/exec": 1.5,
        "text/template": 1.5, "注入": 1.5, "命令执行": 2, "xss": 1,
    },
    "G-AUTH": {
        "authentication bypass": 2, "authorization bypass": 2, "privilege escalation": 2,
        "unauthenticated": 2, "improper authentication": 2, "access control": 1.5,
        "rbac": 1.5, "jwt": 1.5, "token forgery": 2, "alg:none": 2,
        "bypass": 1, "authorization": 1, "认证绕过": 2, "越权": 2, "提权": 2,
        "unauthorized": 1.5, "impersonation": 2, "oidc": 1,
    },
    "G-DOS": {
        "denial of service": 2, "resource exhaustion": 2, "cpu exhaustion": 2,
        "memory exhaustion": 2, "infinite loop": 2, "goroutine leak": 2,
        "http/2 reset": 2, "rapid reset": 2, "regex": 1, "regexdos": 2,
        "amplification": 1.5, "flood": 1.5, "rate limit": 1, "panic": 1,
        "拒绝服务": 2, "内存耗尽": 2, "goroutine 泄漏": 2,
    },
    "G-MEM": {
        "buffer overflow": 2, "out of bounds": 2, "use after free": 2,
        "memory corruption": 2, "unsafe.pointer": 2, "heap overflow": 2,
        "stack overflow": 2, "nil pointer": 1.5, "unsafe": 1,
        "cgo": 1.5, "memory leak": 1, "内存越界": 2, "内存损坏": 2,
    },
    "G-PROTO": {
        "protobuf": 1.5, "yaml": 1, "json": 0.5, "xml": 0.5,
        "deserialization": 2, "unmarshaling": 1.5, "parsing": 0.5,
        "billion laughs": 2, "zip bomb": 2, "message bomb": 2,
        "codec": 1, "序列化": 1.5, "反序列化": 2, "解析": 0.5,
    },
    "G-CRYPTO": {
        "cryptographic": 1.5, "certificate": 1.5, "tls": 1.5, "ssl": 1.5,
        "insecureskipverify": 2, "weak randomness": 2, "math/rand": 2,
        "weak cipher": 2, "key generation": 1, "ecdsa": 1.5, "rsa": 1,
        "signature forgery": 2, "加密": 1, "证书绕过": 2, "密码学": 1.5,
        "sm9": 2, "infinity point": 2, "forgery": 1.5,
    },
    "G-SSRF": {
        "server-side request forgery": 2, "ssrf": 2, "open redirect": 2,
        "unvalidated redirect": 2, "metadata service": 2,
        "internal network": 1.5, "http.client": 1, "url validation": 1.5,
        "dns rebinding": 2, "服务端请求伪造": 2, "内网访问": 2,
    },
    "G-PATH": {
        "path traversal": 2, "directory traversal": 2, "zip slip": 2,
        "symlink": 1.5, "filepath.join": 1.5, "arbitrary file": 2,
        "file read": 1, "file write": 1, "../": 2, "dotdot": 2,
        "路径遍历": 2, "目录穿越": 2, "符号链接": 1.5, "任意文件": 2,
    },
    "G-RACE": {
        "race condition": 2, "data race": 2, "toctou": 2, "time-of-check": 2,
        "concurrent": 1, "mutex": 0.5, "goroutine": 0.5, "sync": 0.5,
        "map concurrent": 2, "竞争条件": 2, "数据竞争": 2, "并发": 1,
    },
    "G-SUPPLY": {
        "supply chain": 2, "typosquatting": 2, "malicious package": 2,
        "module replacement": 2, "go.sum": 1.5, "dependency confusion": 2,
        "compromised dependency": 2, "供应链": 2, "恶意依赖": 2,
    },
}

# 置信度阈值：低于此值认为是潜在新模式
# 使用较低阈值以减少误判，只有完全无法分类的才认为是新模式
NEW_PATTERN_THRESHOLD = 0.10


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class PatternMatch:
    """单次漏洞模式匹配结果。"""
    pattern_id:  str
    confidence:  float           # 0.0 ~ 1.0
    is_new:      bool = False    # 是否为新发现模式
    is_extended: bool = False    # 是否为已有模式的扩展特征


@dataclass
class VulnCharacteristics:
    """从漏洞描述 + 代码 diff 提取的结构化特征。"""
    pattern_id:   str
    pattern_name: str
    is_new_pattern: bool = False

    # 漏洞特征（从描述/diff before 提取）
    vuln_features: list[str] = field(default_factory=list)
    # 代码对比
    before_code:  str = ""
    after_code:   str = ""
    diff_filename: str = ""
    # 防御方案（从 diff after + 模式库提取）
    defense_points: list[str] = field(default_factory=list)
    # 触发条件
    trigger_conditions: list[str] = field(default_factory=list)

    # 新模式元数据（仅当 is_new_pattern=True）
    new_pattern_keywords: list[str] = field(default_factory=list)
    new_pattern_description: str = ""


@dataclass
class DiscoveredPattern:
    """持久化的新发现模式。"""
    id:           str
    name_zh:      str
    name_en:      str
    description:  str
    keywords:     list[str]
    first_seen:   str    # advisory ID
    first_date:   str
    count:        int = 1
    examples:     list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# 模式匹配
# ---------------------------------------------------------------------------

def score_pattern(text: str, pattern_id: str) -> float:
    """
    计算文本与指定模式的匹配得分（0.0 ~ 1.0）。
    归一化方式：命中得分 / 该模式权重最高的 Top-3 关键词之和
    这样单个高置信度命中即可得到较高分数。
    """
    keywords = PATTERN_WEIGHTED_KEYWORDS.get(pattern_id, {})
    if not keywords:
        return 0.0

    text_lower = text.lower()
    hit_score  = sum(w for kw, w in keywords.items() if kw in text_lower)

    # 用 Top-3 高权重关键词的总和作为分母（而非全部关键词）
    top3_weights = sorted(keywords.values(), reverse=True)[:3]
    max_score    = sum(top3_weights)

    if max_score == 0:
        return 0.0
    return min(hit_score / max_score, 1.0)


def classify_with_confidence(advisory: dict) -> PatternMatch:
    """
    为 advisory 计算所有模式的得分，返回最佳匹配。
    若最高置信度 < NEW_PATTERN_THRESHOLD，标记为潜在新模式。
    """
    text = " ".join([
        advisory.get("title", ""),
        advisory.get("description", ""),
        " ".join(advisory.get("cwes", []) or []),
    ])

    scores = {pid: score_pattern(text, pid)
              for pid in PATTERN_WEIGHTED_KEYWORDS}

    best_id    = max(scores, key=lambda k: scores[k])
    best_score = scores[best_id]

    if best_score < NEW_PATTERN_THRESHOLD:
        return PatternMatch(
            pattern_id="G-OTHER",
            confidence=best_score,
            is_new=True,
        )

    return PatternMatch(
        pattern_id=best_id,
        confidence=best_score,
        is_new=False,
    )


# ---------------------------------------------------------------------------
# 新模式自动命名
# ---------------------------------------------------------------------------

# 关键词 -> (Go中文名, 英文名)
_FEATURE_VOCAB: list[tuple[str, str, str]] = [
    ("cors",            "CORS 配置错误",      "CORS Misconfiguration"),
    ("cross-origin",    "跨域资源共享缺陷",    "Cross-Origin Resource Sharing Flaw"),
    ("open redirect",   "开放重定向",          "Open Redirect"),
    ("log injection",   "日志注入",            "Log Injection"),
    ("format string",   "格式字符串",          "Format String"),
    ("integer overflow","整数溢出",            "Integer Overflow"),
    ("integer underflow","整数下溢",           "Integer Underflow"),
    ("nil dereference", "空指针解引用",        "Nil Pointer Dereference"),
    ("header injection","HTTP 头注入",         "HTTP Header Injection"),
    ("http request smuggling", "HTTP 请求走私","HTTP Request Smuggling"),
    ("cache poisoning", "缓存投毒",            "Cache Poisoning"),
    ("env variable",    "环境变量注入",        "Environment Variable Injection"),
    ("timing attack",   "时序攻击",            "Timing Attack"),
    ("type confusion",  "类型混淆",            "Type Confusion"),
    ("prototype pollution", "原型链污染",      "Prototype Pollution"),
    ("graphql",         "GraphQL 注入",        "GraphQL Injection"),
    ("csrf",            "跨站请求伪造",        "CSRF"),
    ("xss",             "跨站脚本",            "XSS"),
    ("xxe",             "XML 外部实体",        "XXE"),
    ("ssti",            "服务端模板注入",      "SSTI"),
    ("idor",            "越权对象直接引用",    "IDOR"),
    ("insecure deserialization","不安全反序列化","Insecure Deserialization"),
    ("mass assignment", "批量赋值",            "Mass Assignment"),
    ("weak password",   "弱密码",              "Weak Password Policy"),
    ("session fixation","会话固定",            "Session Fixation"),
    ("clickjacking",    "点击劫持",            "Clickjacking"),
    ("subdomain takeover","子域名接管",         "Subdomain Takeover"),
    ("http/2",          "HTTP/2 协议漏洞",     "HTTP/2 Protocol Vulnerability"),
    ("grpc",            "gRPC 协议漏洞",       "gRPC Protocol Vulnerability"),
    ("websocket",       "WebSocket 安全",      "WebSocket Security"),
]


def _extract_new_pattern_name(advisory: dict) -> tuple[str, str, list[str]]:
    """
    从 advisory 描述中推断新模式的名称和关键词。
    返回 (name_zh, name_en, keywords)。
    """
    text = " ".join([advisory.get("title", ""), advisory.get("description", "")]).lower()

    for kw, zh, en in _FEATURE_VOCAB:
        if kw in text:
            # 提取文本中出现的相关词汇作为关键词
            words = re.findall(r'\b[a-z][a-z0-9\-/]{2,}\b', text)
            stop = {"the", "and", "for", "that", "this", "with", "from", "are",
                    "can", "use", "using", "used", "when", "which", "have",
                    "been", "not", "but", "may", "allow", "allows"}
            keywords = list(dict.fromkeys(
                w for w in words if len(w) > 3 and w not in stop
            ))[:8]
            return zh, en, [kw] + keywords

    # 找不到预定义词汇，从标题提取
    title = advisory.get("title", "Unknown")
    # 提取括号外的核心词
    title_clean = re.sub(r'\([^)]*\)', '', title).strip()
    # 取前4个单词
    parts = [w for w in title_clean.split() if len(w) > 2][:4]
    name_en = " ".join(parts) or "Unknown Pattern"
    name_zh = name_en  # 无法自动翻译时保留英文

    words = re.findall(r'\b[a-z][a-z0-9\-]{2,}\b', text)
    keywords = list(dict.fromkeys(w for w in words if len(w) > 3))[:6]
    return name_zh, name_en, keywords


# ---------------------------------------------------------------------------
# 持久化新模式库
# ---------------------------------------------------------------------------

def _load_discovered_patterns() -> dict[str, DiscoveredPattern]:
    """从文件加载已发现的新模式。"""
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
    nums = []
    for k in existing:
        m = re.match(r'G-NEW-(\d+)', k)
        if m:
            nums.append(int(m.group(1)))
    n = max(nums) + 1 if nums else 1
    return f"G-NEW-{n:03d}"


def register_new_pattern(
    advisory: dict,
    name_zh: str,
    name_en: str,
    keywords: list[str],
    description: str,
    date_str: str,
) -> str:
    """
    将新模式注册/更新到持久化库中，返回分配的 pattern_id。
    如果关键词与已有新模式高度重叠，则合并而不是新建。
    """
    patterns = _load_discovered_patterns()
    vid = advisory.get("id") or advisory.get("cve_id") or ""

    # 检查是否与已有新模式重复（关键词重叠 >= 50%）
    for pid, p in patterns.items():
        overlap = len(set(keywords) & set(p.keywords))
        if overlap >= max(1, len(keywords) // 2):
            p.count += 1
            if vid and vid not in p.examples:
                p.examples.append(vid)
            _save_discovered_patterns(patterns)
            return pid

    # 注册新模式
    new_id = _next_pattern_id(patterns)
    patterns[new_id] = DiscoveredPattern(
        id=new_id,
        name_zh=name_zh,
        name_en=name_en,
        description=description,
        keywords=keywords,
        first_seen=vid,
        first_date=date_str,
        count=1,
        examples=[vid] if vid else [],
    )
    _save_discovered_patterns(patterns)
    return new_id


def get_discovered_patterns() -> dict[str, DiscoveredPattern]:
    return _load_discovered_patterns()


# ---------------------------------------------------------------------------
# 特征提取
# ---------------------------------------------------------------------------

# 漏洞特征提取模板（每个模式的关键特征句模板）
PATTERN_VULN_FEATURES: dict[str, list[str]] = {
    "G-INJ": [
        "用户输入未经过滤直接拼接到查询/命令字符串",
        "使用 text/template 而非 html/template 渲染用户数据",
        "exec.Command 以 shell 字符串形式传递用户输入",
        "数据库查询语句通过字符串格式化构造",
    ],
    "G-AUTH": [
        "认证校验逻辑可被绕过（条件判断存在缺陷）",
        "权限检查在请求处理链路中位置错误或缺失",
        "JWT 未校验签名算法类型，允许 alg:none",
        "服务间调用缺乏充分的身份验证机制",
    ],
    "G-DOS": [
        "处理用户可控输入时无大小/数量上限限制",
        "存在可被触发的无限循环或递归调用路径",
        "goroutine 在特定条件下无法退出，导致泄漏",
        "HTTP/2 流或帧处理未做并发数量限制",
    ],
    "G-MEM": [
        "unsafe.Pointer 转换未经边界检查",
        "切片索引操作缺乏长度验证",
        "cgo 接口未对 C 端数据大小进行校验",
    ],
    "G-PROTO": [
        "反序列化时未限制最大消息体积",
        "YAML/JSON 解析器接受用户任意提供的类型",
        "Protobuf 嵌套消息深度无上限限制",
    ],
    "G-CRYPTO": [
        "使用 math/rand 代替 crypto/rand 生成安全相关随机数",
        "TLS 配置允许低版本协议或弱 cipher suite",
        "证书验证被 InsecureSkipVerify=true 禁用",
        "密码学算法参数（如 P 点）来自不可信输入",
    ],
    "G-SSRF": [
        "HTTP 客户端未过滤私有 IP 地址段",
        "用户提供的 URL 直接传递给 http.Get/http.Client",
        "重定向跟随策略未限制目标地址范围",
    ],
    "G-PATH": [
        "filepath.Join 未验证用户输入是否包含 '../' 序列",
        "文件操作目标路径未确认在允许目录之内",
        "解压 tar/zip 时未验证 entry 路径是否逃逸根目录",
    ],
    "G-RACE": [
        "多 goroutine 并发读写共享 map 未加锁",
        "check-then-act 操作之间存在竞争窗口（TOCTOU）",
        "全局变量或共享状态在并发访问时缺乏同步",
    ],
    "G-SUPPLY": [
        "第三方依赖包路径易被仿冒（typosquatting）",
        "go.mod 未锁定精确版本，依赖可被替换",
        "构建流程从未经验证的来源下载依赖",
    ],
}

# 防御特征模板
PATTERN_DEFENSE_POINTS: dict[str, list[str]] = {
    "G-INJ": [
        "使用参数化查询（database/sql 的 `?` 占位符）或 ORM",
        "命令执行使用参数数组 exec.Command(\"cmd\", arg1, arg2)，禁用 shell=true",
        "输出 HTML 时使用 html/template，利用自动转义",
        "所有外部输入进行白名单验证后再使用",
    ],
    "G-AUTH": [
        "统一在中间件层做认证鉴权，不在 handler 内分散处理",
        "JWT 解析时强制校验 token.Method 类型",
        "使用 crypto/subtle.ConstantTimeCompare 进行 token 比较",
        "服务间调用启用 mTLS 或 HMAC 签名验证",
    ],
    "G-DOS": [
        "所有 HTTP handler 包装 http.TimeoutHandler，设置合理超时",
        "使用 http.MaxBytesReader 限制请求体大小",
        "限制 goroutine 最大并发数，使用 worker pool 模式",
        "HTTP/2 Server 配置 MaxConcurrentStreams 上限",
    ],
    "G-MEM": [
        "unsafe 操作前做完整边界检查，使用 len/cap 验证",
        "cgo 接口传入 C 函数前验证指针有效性和数据长度",
        "开启 go test -race 和模糊测试发现内存问题",
    ],
    "G-PROTO": [
        "设置 grpc.MaxRecvMsgSize / grpc.MaxSendMsgSize 限制消息大小",
        "YAML 使用 gopkg.in/yaml.v3 并调用 decoder.KnownFields(true)",
        "反序列化前验证数据大小，拒绝超过限制的输入",
    ],
    "G-CRYPTO": [
        "所有随机数生成使用 crypto/rand，禁止 math/rand 用于安全场景",
        "TLS 配置 MinVersion: tls.VersionTLS12，移除弱 cipher suite",
        "生产环境禁止 InsecureSkipVerify，配置正确的 CA bundle",
        "密码学算法参数来自受信任来源，输入前做有效性检验",
    ],
    "G-SSRF": [
        "自定义 http.Transport.DialContext，过滤私有 IP 段（RFC 1918 + 169.254.x.x）",
        "设置 CheckRedirect: func() error { return http.ErrUseLastResponse }",
        "目标 URL 使用白名单域名验证，拒绝 IP 直连",
    ],
    "G-PATH": [
        "使用 filepath.Rel 验证最终路径在 base 目录内",
        "解压 archive 时对每个 entry 检查 filepath.Clean 后是否含 '..'",
        "Go 1.24+ 使用 os.OpenRoot 做沙箱文件操作",
    ],
    "G-RACE": [
        "共享 map 访问用 sync.RWMutex 保护，或改用 sync.Map",
        "atomic 操作替代简单整数的并发读写",
        "CI 流水线加入 go test -race ./... 强制检测",
    ],
    "G-SUPPLY": [
        "启用 GONOSUMCHECK=off，所有依赖经 go.sum 验证",
        "定期运行 govulncheck ./... 检查已知 CVE",
        "私有 GOPROXY 镜像 + 依赖审计，避免 typosquatting",
    ],
}


def extract_characteristics_from_diff(
    advisory: dict,
    patch_info,  # PatchInfo | None
    pattern_id: str,
) -> VulnCharacteristics:
    """
    综合 advisory 描述 + code diff 提取结构化漏洞特征。
    patch_info 为可选的 PatchInfo 对象（含 go_diffs 列表）。
    """

    pattern_name = _pattern_display_name(pattern_id)
    is_new = pattern_id.startswith("G-NEW-")

    # 漏洞特征：先用模板，再从描述提取补充
    vuln_features = list(PATTERN_VULN_FEATURES.get(pattern_id, [])[:3])
    vuln_features += _extract_features_from_description(advisory.get("description", ""))

    # 防御方案
    defense_points = list(PATTERN_DEFENSE_POINTS.get(pattern_id, [])[:4])
    if not defense_points and is_new:
        defense_points = ["参考 references/go_vuln_patterns.md 通用加固方案"]

    # 触发条件
    trigger_conditions = _extract_trigger_conditions(advisory)

    char = VulnCharacteristics(
        pattern_id=pattern_id,
        pattern_name=pattern_name,
        is_new_pattern=is_new,
        vuln_features=vuln_features[:4],
        defense_points=defense_points[:4],
        trigger_conditions=trigger_conditions,
    )

    # 从 diff 补充代码对比
    if patch_info and patch_info.go_diffs:
        best_diff = _select_best_diff(patch_info.go_diffs)
        if best_diff:
            char.before_code = _format_code_lines(best_diff.before_lines, max_lines=12)
            char.after_code  = _format_code_lines(best_diff.after_lines,  max_lines=12)
            char.diff_filename = best_diff.filename

    return char


def _select_best_diff(diffs) -> object | None:
    """选择最有代表性的 Go diff（优先选择非测试文件、修改行数适中的）。"""
    if not diffs:
        return None
    candidates = [d for d in diffs if not d.filename.endswith("_test.go")]
    if not candidates:
        candidates = diffs
    # 选修改行最多（但不超过 20 行）的
    scored = [(d, len(d.before_lines) + len(d.after_lines)) for d in candidates]
    scored = [(d, s) for d, s in scored if 1 <= s <= 30]
    if not scored:
        return candidates[0]
    return max(scored, key=lambda x: x[1])[0]


def _format_code_lines(lines: list[str], max_lines: int = 12) -> str:
    if not lines:
        return ""
    trimmed = lines[:max_lines]
    code = "\n".join(trimmed)
    if len(lines) > max_lines:
        code += f"\n// ... 省略 {len(lines) - max_lines} 行"
    return code


def _extract_features_from_description(desc: str) -> list[str]:
    """从描述文本提取额外特征句。"""
    features = []
    if not desc:
        return features

    # 提取含有"allow"/"can"/"enables"的句子作为漏洞特征
    sentences = re.split(r'[.!?]', desc)
    keywords = ["allow", "can", "enables", "expose", "leak", "bypass",
                 "arbitrary", "unauthenticated", "without authentication",
                 "允许", "可以", "暴露", "泄露", "绕过"]
    for sent in sentences[:6]:
        sent = sent.strip()
        if 20 < len(sent) < 200:
            if any(kw in sent.lower() for kw in keywords):
                features.append(sent)
    return features[:2]


def _extract_trigger_conditions(advisory: dict) -> list[str]:
    """从描述中提取触发条件。"""
    conditions = []
    text = advisory.get("description", "").lower()

    if "unauthenticated" in text or "no authentication" in text:
        conditions.append("无需认证即可触发（远程匿名攻击者）")
    if "network" in text or "remote" in text:
        conditions.append("攻击者可通过网络远程触发")
    if "local" in text:
        conditions.append("需要本地访问权限")
    if "authenticated user" in text or "logged-in" in text:
        conditions.append("需要普通用户认证凭证")
    if "admin" in text or "privileged" in text:
        conditions.append("需要管理员权限")
    if "crafted" in text or "malicious" in text:
        conditions.append("需要构造特殊格式的输入数据")

    return conditions[:3] if conditions else ["详见漏洞描述"]


def _pattern_display_name(pattern_id: str) -> str:
    names = {
        "G-INJ":    "注入类漏洞",
        "G-AUTH":   "认证/授权绕过",
        "G-DOS":    "拒绝服务（DoS）",
        "G-MEM":    "内存安全",
        "G-PROTO":  "协议/序列化漏洞",
        "G-CRYPTO": "密码学问题",
        "G-SSRF":   "服务端请求伪造",
        "G-PATH":   "路径遍历",
        "G-RACE":   "竞争条件",
        "G-SUPPLY": "供应链安全",
        "G-OTHER":  "其他/未分类",
    }
    if pattern_id in names:
        return names[pattern_id]
    # 新发现模式：尝试从缓存中读取名称
    discovered = get_discovered_patterns()
    if pattern_id in discovered:
        return discovered[pattern_id].name_zh
    return pattern_id


# ---------------------------------------------------------------------------
# 批量分析接口
# ---------------------------------------------------------------------------

def analyze_all(
    advisories: list[dict],
    patches: dict,        # {advisory_id: PatchInfo}
    date_str: str,
) -> list[dict]:
    """
    对所有 advisory 进行模式分析和特征提取，返回增强后的 advisory 列表。
    为每条 advisory 新增字段：
      - category: 模式 ID（可能是 G-NEW-XXX）
      - category_confidence: 置信度
      - is_new_pattern: bool
      - characteristics: VulnCharacteristics（序列化为 dict）
    """
    enhanced = []

    for adv in advisories:
        match = classify_with_confidence(adv)
        vid = adv.get("id") or adv.get("cve_id") or adv.get("ghsa_id") or ""

        # 如果是新模式，注册它
        if match.is_new:
            name_zh, name_en, keywords = _extract_new_pattern_name(adv)
            desc = (adv.get("description") or "")[:200]
            new_id = register_new_pattern(adv, name_zh, name_en, keywords, desc, date_str)
            match.pattern_id = new_id

        adv["category"] = match.pattern_id
        adv["category_confidence"] = round(match.confidence, 3)
        adv["is_new_pattern"] = match.is_new

        # 提取结构化特征
        patch_info = patches.get(vid) if patches else None
        char = extract_characteristics_from_diff(adv, patch_info, match.pattern_id)
        adv["characteristics"] = asdict(char)

        enhanced.append(adv)

    return enhanced
