"""
代码补丁抓取模块
从 advisory 的引用链接中提取 GitHub commit/PR，抓取 Go 代码的修改前后对比。
支持通过代理访问，遵守 GitHub API 速率限制。
"""

import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import requests

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------

@dataclass
class HunkLine:
    """Diff 中的一行。"""
    kind: str   # "context" | "removed" | "added"
    text: str


@dataclass
class FileDiff:
    """单个 Go 文件的差异。"""
    filename: str
    old_filename: str
    before_lines: list[str] = field(default_factory=list)  # 被删除的行（漏洞代码）
    after_lines:  list[str] = field(default_factory=list)  # 新增的行（修复代码）
    context_lines: list[str] = field(default_factory=list) # 上下文行
    patch_snippet: str = ""  # 完整 diff 片段（用于展示）


@dataclass
class PatchInfo:
    """一个 advisory 的补丁信息。"""
    commit_url: str = ""
    pr_url: str = ""
    commit_sha: str = ""
    repo_full: str = ""          # "owner/repo"
    go_diffs: list[FileDiff] = field(default_factory=list)
    commit_message: str = ""
    fetch_error: str = ""


# ---------------------------------------------------------------------------
# URL 解析
# ---------------------------------------------------------------------------

_COMMIT_RE = re.compile(
    r'https?://github\.com/([^/]+/[^/]+)/commit/([0-9a-f]{7,40})',
    re.IGNORECASE,
)
_PR_RE = re.compile(
    r'https?://github\.com/([^/]+/[^/]+)/pull/(\d+)',
    re.IGNORECASE,
)
_COMPARE_RE = re.compile(
    r'https?://github\.com/([^/]+/[^/]+)/compare/[^.]+\.\.\.([0-9a-f]{7,40})',
    re.IGNORECASE,
)


def _extract_commit_urls(advisory: dict) -> list[tuple[str, str]]:
    """
    从 advisory 的 references 和 _raw 字段中提取 (repo_full, sha) 对。
    返回列表，优先返回 commit，其次 compare，最后 PR（需要额外请求）。
    """
    results = []
    seen_shas = set()

    refs = advisory.get("references", [])
    # 也搜索 _raw 中的所有 URL
    raw_refs = []
    raw = advisory.get("_raw", {})
    for r in raw.get("references", []):
        url = r if isinstance(r, str) else r.get("url", "")
        if url:
            raw_refs.append(url)

    all_urls = list(refs) + raw_refs

    for url in all_urls:
        # 直接 commit
        m = _COMMIT_RE.search(url)
        if m:
            repo, sha = m.group(1), m.group(2)
            if sha not in seen_shas:
                seen_shas.add(sha)
                results.append((repo, sha, "commit"))
            continue

        # compare URL（取 ...{sha} 之后的部分）
        m = _COMPARE_RE.search(url)
        if m:
            repo, sha = m.group(1), m.group(2)
            if sha not in seen_shas:
                seen_shas.add(sha)
                results.append((repo, sha, "commit"))
            continue

    return results[:3]  # 最多取 3 个 commit，避免过多请求


# ---------------------------------------------------------------------------
# GitHub API 请求
# ---------------------------------------------------------------------------

def _github_get(session: requests.Session, url: str,
                accept: str = "application/vnd.github+json",
                retries: int = 2) -> requests.Response | None:
    for attempt in range(retries + 1):
        try:
            resp = session.get(
                url,
                headers={"Accept": accept, "X-GitHub-Api-Version": "2022-11-28"},
                timeout=20,
            )
            if resp.status_code == 429 or resp.status_code == 403:
                # 速率限制
                wait = int(resp.headers.get("Retry-After", "10"))
                time.sleep(min(wait, 30))
                continue
            return resp
        except requests.exceptions.RequestException:
            if attempt < retries:
                time.sleep(2 ** attempt)
    return None


# ---------------------------------------------------------------------------
# Diff 解析
# ---------------------------------------------------------------------------

def _parse_unified_diff(diff_text: str) -> list[FileDiff]:
    """解析 unified diff 格式，提取 Go 文件的修改前后代码。"""
    files: list[FileDiff] = []
    current: FileDiff | None = None

    for line in diff_text.splitlines():
        # 新文件开始
        if line.startswith("diff --git"):
            if current and current.filename.endswith(".go"):
                files.append(current)
            current = None

        elif line.startswith("+++ b/"):
            filename = line[6:].strip()
            if filename.endswith(".go") and not filename.endswith("_test.go"):
                old_name = ""
                current = FileDiff(filename=filename, old_filename=old_name)

        elif line.startswith("--- a/"):
            if current:
                current.old_filename = line[6:].strip()

        elif current is not None:
            if line.startswith("-") and not line.startswith("---"):
                text = line[1:].rstrip()
                if text.strip() and not text.strip().startswith("//"):
                    current.before_lines.append(text)
                current.patch_snippet += line + "\n"

            elif line.startswith("+") and not line.startswith("+++"):
                text = line[1:].rstrip()
                if text.strip() and not text.strip().startswith("//"):
                    current.after_lines.append(text)
                current.patch_snippet += line + "\n"

            elif line.startswith("@@"):
                current.patch_snippet += line + "\n"

            elif not line.startswith("\\"):
                text = line.rstrip()
                if text.strip():
                    current.context_lines.append(text)
                current.patch_snippet += line + "\n"

    if current and current.filename.endswith(".go"):
        files.append(current)

    # 只保留有实质内容的 diff（超过 2 行修改）
    return [f for f in files if len(f.before_lines) + len(f.after_lines) >= 2]


def _trim_diff(fd: FileDiff, max_lines: int = 30) -> FileDiff:
    """裁剪过长的 diff，保留最有代表性的部分。"""
    fd.before_lines = fd.before_lines[:max_lines]
    fd.after_lines  = fd.after_lines[:max_lines]
    # 只保留 patch 的前 60 行
    lines = fd.patch_snippet.splitlines()[:60]
    fd.patch_snippet = "\n".join(lines)
    return fd


# ---------------------------------------------------------------------------
# 主函数
# ---------------------------------------------------------------------------

def fetch_patch_for_advisory(
    advisory: dict,
    session: requests.Session,
    verbose: bool = False,
) -> PatchInfo:
    """
    尝试为一条 advisory 抓取修复补丁信息。
    返回 PatchInfo，若无法获取则 go_diffs 为空，fetch_error 包含原因。
    """
    patch = PatchInfo()
    commit_refs = _extract_commit_urls(advisory)

    if not commit_refs:
        patch.fetch_error = "no_commit_url"
        return patch

    for repo_full, sha, kind in commit_refs:
        patch.repo_full = repo_full
        patch.commit_sha = sha
        patch.commit_url = f"https://github.com/{repo_full}/commit/{sha}"

        if verbose:
            print(f"      Fetching diff: {patch.commit_url}")

        # 先获取 commit 元数据（commit message）
        meta_resp = _github_get(
            session,
            f"https://api.github.com/repos/{repo_full}/commits/{sha}",
        )
        if meta_resp and meta_resp.status_code == 200:
            meta = meta_resp.json()
            patch.commit_message = (meta.get("commit", {}).get("message", "") or "")[:200]

        # 获取 diff
        diff_resp = _github_get(
            session,
            f"https://api.github.com/repos/{repo_full}/commits/{sha}",
            accept="application/vnd.github.diff",
        )

        if diff_resp is None or diff_resp.status_code != 200:
            patch.fetch_error = f"http_{diff_resp.status_code if diff_resp else 'timeout'}"
            time.sleep(0.5)
            continue

        diff_text = diff_resp.text
        go_diffs = _parse_unified_diff(diff_text)

        if go_diffs:
            patch.go_diffs = [_trim_diff(d) for d in go_diffs[:5]]  # 最多 5 个文件
            break

        time.sleep(0.3)

    if not patch.go_diffs and not patch.fetch_error:
        patch.fetch_error = "no_go_changes"

    return patch


def batch_fetch_patches(
    advisories: list[dict],
    session: requests.Session,
    max_fetch: int = 30,
    verbose: bool = False,
) -> dict[str, PatchInfo]:
    """
    批量抓取补丁，只处理 CRITICAL/HIGH 级别（或所有，若 max_fetch 足够）。
    返回 {advisory_id: PatchInfo} 字典。
    """
    # 优先处理高危漏洞
    priority = [v for v in advisories if v.get("severity") in ("CRITICAL", "HIGH")]
    rest     = [v for v in advisories if v.get("severity") not in ("CRITICAL", "HIGH")]
    ordered  = priority + rest

    patches: dict[str, PatchInfo] = {}
    fetched  = 0

    for adv in ordered:
        if fetched >= max_fetch:
            break

        vid = adv.get("id") or adv.get("cve_id") or adv.get("ghsa_id")
        if not vid:
            continue

        # 只处理有 GitHub 引用的漏洞
        refs = adv.get("references", []) + list(
            (r if isinstance(r, str) else r.get("url", ""))
            for r in adv.get("_raw", {}).get("references", [])
        )
        if not any("github.com" in str(r) for r in refs):
            continue

        patch = fetch_patch_for_advisory(adv, session, verbose=verbose)
        patches[vid] = patch
        fetched += 1
        time.sleep(0.2)  # 礼貌性限速

    return patches
